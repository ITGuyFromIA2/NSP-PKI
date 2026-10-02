<#
.SYNOPSIS
    Shared helpers for the VPN certificate evaluation harness (Build-VPNCertEvalTargets.ps1 +
    Invoke-VPNCertEval.ps1). Dot-source this file from the same folder.

.DESCRIPTION
    Pure/near-pure helpers - reachability probes lifted from Examples_Sources\User-UnitTests (3).ps1,
    plus PFX-stem parsing, subject-DN OU extraction, a certutil -verify verdict parser, a tiny .psd1
    serializer, and the built-in service->port catalog. Nothing here connects a VPN or mutates a
    cert store; the runner does that.

.NOTES
    Windows PowerShell 5.1 safe (no ternary, no ??, no classes). Get-NetAdapter / Get-NetIPAddress
    are used opportunistically for tunnel detail but the load-bearing up/down signal is a marker-host
    ping so it does not matter how FortiClient names (or whether it creates) an adapter.

    No top-level side effects - safe to dot-source. The entry scripts set their own Set-StrictMode.
#>

# --------------------------------------------------------------------------------------------------
# Property access that tolerates strict mode + missing members (JSON objects are ragged)
# --------------------------------------------------------------------------------------------------
function Get-EvalProp {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] } else { return $Default }
    }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $Default
}

# --------------------------------------------------------------------------------------------------
# Reachability probes  (from User-UnitTests (3).ps1, parameterised on timeout)
# --------------------------------------------------------------------------------------------------
function Test-EvalTcpPort {
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][int]$Port, [int]$TimeoutMs = 500)
    $tcp = [System.Net.Sockets.TcpClient]::new()
    try {
        $ar = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok) { $tcp.EndConnect($ar) }
        return [bool]$ok
    } catch { return $false }
    finally { $tcp.Close() }
}

function Test-EvalUdpPort {
    # UDP is connectionless: a timeout is ambiguous (open|filtered) and is reported as "not blocked".
    # Only an ICMP port-unreachable (ConnectionReset) is a definite closed/blocked.
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][int]$Port, [int]$TimeoutMs = 500)
    $udp = [System.Net.Sockets.UdpClient]::new()
    $udp.Client.ReceiveTimeout = $TimeoutMs
    try {
        $udp.Connect($ComputerName, $Port)
        [void]$udp.Send([byte[]]@(0x00), 1)
        $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        [void]$udp.Receive([ref]$ep)
        return $true
    } catch [System.Net.Sockets.SocketException] {
        return ($_.Exception.SocketErrorCode -ne [System.Net.Sockets.SocketError]::ConnectionReset)
    } catch { return $false }
    finally { $udp.Close() }
}

function Test-EvalPing {
    param([Parameter(Mandatory)][string]$ComputerName, [int]$TimeoutMs = 500)
    $p = [System.Net.NetworkInformation.Ping]::new()
    try {
        $reply = $p.Send($ComputerName, $TimeoutMs)
        return ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
    } catch { return $false }
    finally { $p.Dispose() }
}

# --------------------------------------------------------------------------------------------------
# Tunnel state
# --------------------------------------------------------------------------------------------------
function Get-EvalTunnelState {
    <#
    .SYNOPSIS
        Best-effort snapshot of whether a FortiClient VPN tunnel is up. -MarkerHost (an address that
        is ONLY reachable across the tunnel) is the authoritative signal; adapter details are extra.
    #>
    param([string]$MarkerHost, [int]$PingTimeoutMs = 800)

    $adapter = $null; $ip = $null; $dns = @()
    try {
        if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
            $adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object { ($_.InterfaceDescription -match 'Forti' -or $_.Name -match 'Forti|FortiClient|SSL ?VPN|IPsec') -and $_.Status -eq 'Up' } |
                Select-Object -First 1
        }
        if ($adapter -and (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue)) {
            $ip = (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notmatch '^169\.254\.' } | Select-Object -First 1 -ExpandProperty IPAddress)
        }
        if ($adapter -and (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue)) {
            $dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty ServerAddresses)
        }
    } catch { }

    $markerUp = $null
    if ($MarkerHost) { $markerUp = Test-EvalPing -ComputerName $MarkerHost -TimeoutMs $PingTimeoutMs }

    # Up if the marker answers; if no marker given, fall back to "a Forti adapter is up with a routable IP".
    $up = $false
    if ($null -ne $markerUp) { $up = [bool]$markerUp }
    elseif ($adapter -and $ip) { $up = $true }

    return [pscustomobject]@{
        Up          = $up
        MarkerHost  = $MarkerHost
        MarkerPing  = $markerUp
        AdapterName = if ($adapter) { $adapter.Name } else { $null }
        AssignedIP  = $ip
        DnsServers  = $dns
    }
}

function Wait-EvalTunnel {
    param(
        [Parameter(Mandatory)][ValidateSet('up', 'down')][string]$State,
        [string]$MarkerHost,
        [int]$TimeoutSec = 30,
        [int]$PollSec = 3
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $last = $null
    do {
        $last = Get-EvalTunnelState -MarkerHost $MarkerHost
        $hit = if ($State -eq 'up') { $last.Up } else { -not $last.Up }
        if ($hit) { return $last }
        Start-Sleep -Seconds $PollSec
    } while ((Get-Date) -lt $deadline)
    return $last
}

# --------------------------------------------------------------------------------------------------
# Certificate helpers
# --------------------------------------------------------------------------------------------------
function Get-CertSubjectOU {
    <# Returns every OU= RDN value from a subject/DN string, outermost first as X.500 prints them. #>
    param([string]$Subject)
    if ([string]::IsNullOrWhiteSpace($Subject)) { return @() }
    $m = [regex]::Matches($Subject, 'OU=("(?:[^"]*)"|[^,]+)', 'IgnoreCase')
    $out = @()
    foreach ($x in $m) { $out += $x.Groups[1].Value.Trim().Trim('"') }
    return $out
}

function Get-CertUtilRevocationVerdict {
    <#
    .SYNOPSIS
        Classifies the text of `certutil -verify -urlfetch <cer>` into Good / Revoked / Undetermined,
        and notes whether a CRL and/or OCSP responder was actually consulted.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $t = if ($null -eq $Text) { '' } else { $Text }

    $revoked = ($t -match 'CRYPT_E_REVOKED' -or $t -match '0x80092010' -or
                $t -match 'certificate is revoked' -or $t -match '\bis revoked\b')
    $offline = ($t -match 'CRYPT_E_REVOCATION_OFFLINE' -or $t -match '0x80092013' -or
                $t -match 'revocation server was offline' -or $t -match 'unable to check revocation' -or
                $t -match 'CRYPT_E_NO_REVOCATION_CHECK' -or $t -match '0x80092012' -or
                $t -match 'RETRIEVAL_FAILURE')
    $good = ($t -match 'Leaf certificate revocation check passed' -or
             $t -match '-verify command completed successfully')

    $verdict = 'Undetermined'
    if ($revoked)      { $verdict = 'Revoked' }
    elseif ($good -and -not $offline) { $verdict = 'Good' }
    elseif ($offline)  { $verdict = 'Undetermined' }

    $crlChecked  = ($t -match 'Verifying CRL' -or $t -match 'Base CRL' -or $t -match 'Delta CRL' -or $t -match 'CRL[^\r\n]*Verified')
    $ocspChecked = ($t -match 'Verifying OCSP' -or $t -match '"OCSP"' -or $t -match 'OCSP[^\r\n]*Time:')

    return [pscustomobject]@{
        Verdict     = $verdict
        Revoked     = [bool]$revoked
        Offline     = [bool]$offline
        CrlChecked  = [bool]$crlChecked
        OcspChecked = [bool]$ocspChecked
        Raw         = $t
    }
}

# --------------------------------------------------------------------------------------------------
# PFX-suite inventory
# --------------------------------------------------------------------------------------------------
function ConvertFrom-EvalPfxStem {
    <#
    .SYNOPSIS
        Splits a New-CATestCertSuite PFX file stem "<UserSanitized>_<LabelSanitized>_<valid|revoked>"
        back into its parts. Returns $null if the stem does not match.
    #>
    param([Parameter(Mandatory)][string]$Stem)
    $m = [regex]::Match($Stem, '^(?<user>[A-Za-z0-9]+)_(?<label>[A-Za-z0-9]+)_(?<kind>valid|revoked)$', 'IgnoreCase')
    if (-not $m.Success) { return $null }
    return [pscustomobject]@{
        User = $m.Groups['user'].Value
        Label = $m.Groups['label'].Value
        Kind = $m.Groups['kind'].Value.ToLowerInvariant()
    }
}

function Get-EvalPfxInventory {
    <#
    .SYNOPSIS
        Enumerates *.pfx in -PfxDir, parses each stem, and (optionally) cross-references a
        <Company>_CertTestSuite_<ts>.txt summary for the authoritative serial / thumbprint / revoked flag.
    #>
    param([Parameter(Mandatory)][string]$PfxDir, [string]$SummaryPath)

    $summaryRows = @()
    if ($SummaryPath -and (Test-Path $SummaryPath)) {
        $lines = Get-Content -Path $SummaryPath
        $cur = $null
        foreach ($ln in $lines) {
            $mRow = [regex]::Match($ln, '^\s*(\S+)\s+(valid|revoked)\s+(\S+)\s+(\S+)\s+(True|False)\s+(.*)$', 'IgnoreCase')
            if ($mRow.Success) {
                $cur = [pscustomobject]@{
                    Label = $mRow.Groups[1].Value; Kind = $mRow.Groups[2].Value.ToLowerInvariant()
                    User = $mRow.Groups[3].Value; Status = $mRow.Groups[4].Value
                    RevokedConfirmed = [bool]::Parse($mRow.Groups[5].Value)
                    Pfx = $mRow.Groups[6].Value.Trim(); Serial = $null; Thumbprint = $null
                }
                $summaryRows += $cur
                continue
            }
            $mSer = [regex]::Match($ln, 'serial\s+([0-9a-fA-F]+)\s+thumbprint\s+([0-9a-fA-F]+)', 'IgnoreCase')
            if ($mSer.Success -and $cur) { $cur.Serial = $mSer.Groups[1].Value; $cur.Thumbprint = $mSer.Groups[2].Value }
        }
    }

    $out = @()
    foreach ($f in (Get-ChildItem -Path $PfxDir -Filter '*.pfx' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $parts = ConvertFrom-EvalPfxStem -Stem $f.BaseName
        if (-not $parts) { continue }
        $match = $summaryRows | Where-Object {
            $_.Kind -eq $parts.Kind -and (
                ($_.User -replace '[^A-Za-z0-9]', '') -ieq $parts.User -or
                ($_.Label -replace '[^A-Za-z0-9]', '') -ieq $parts.Label)
        } | Select-Object -First 1
        $out += [pscustomobject]@{
            PfxPath           = $f.FullName
            FileName          = $f.Name
            User              = $parts.User
            Label             = $parts.Label
            Kind              = $parts.Kind
            ExpectRevoked     = ($parts.Kind -eq 'revoked')
            SummaryLabel      = if ($match) { $match.Label } else { $null }
            SerialFromSummary = if ($match) { $match.Serial } else { $null }
            ThumbFromSummary  = if ($match) { $match.Thumbprint } else { $null }
            RevokeConfirmed   = if ($match) { $match.RevokedConfirmed } else { $null }
        }
    }
    return $out
}

# --------------------------------------------------------------------------------------------------
# Quoted-list parsing (matches the CLIBuilder `"a" "b" "c"` convention used throughout the answers)
# --------------------------------------------------------------------------------------------------
function ConvertFrom-EvalQuotedList {
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $m = [regex]::Matches($Text, '"([^"]+)"')
    if ($m.Count -gt 0) { return @($m | ForEach-Object { $_.Groups[1].Value.Trim() } | Where-Object { $_ }) }
    return @($Text -split '\s+' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ })
}

# --------------------------------------------------------------------------------------------------
# Service catalogue  (service name -> @{ TCP = @(ports); UDP = @(ports) })
# Seeded from User-UnitTests (3).ps1 $ServiceChecks; a -UnitTestsPath merge can override / extend.
# --------------------------------------------------------------------------------------------------
function Get-EvalServiceCatalog {
    return [ordered]@{
        'Ping'      = @{ TCP = @();            UDP = @() }          # handled specially (ICMP)
        'DNS'       = @{ TCP = @(53);          UDP = @(53) }
        'NTP'       = @{ TCP = @();            UDP = @(123) }
        'Kerberos'  = @{ TCP = @(88, 464);     UDP = @(88, 464) }
        'LDAP'      = @{ TCP = @(389);         UDP = @(389) }
        'LDAPS'     = @{ TCP = @(636);         UDP = @() }
        'GlobalCat' = @{ TCP = @(3268, 3269);  UDP = @() }
        'DCE-RPC'   = @{ TCP = @(135);         UDP = @(135) }
        'DynRPC'    = @{ TCP = @(49152);       UDP = @() }
        'RDP'       = @{ TCP = @(3389);        UDP = @(3389) }
        'SMB'       = @{ TCP = @(445);         UDP = @() }
        'SIP'       = @{ TCP = @(5060);        UDP = @(5060) }
        '3CX-5001'  = @{ TCP = @(5001);        UDP = @() }
        'SSH'       = @{ TCP = @(22);          UDP = @() }
        'Telnet'    = @{ TCP = @(23);          UDP = @() }
        'HTTP'      = @{ TCP = @(80);          UDP = @() }
        'HTTPS'     = @{ TCP = @(443);         UDP = @() }
    }
}

function Get-EvalServiceNamesForGroup {
    <#
    .SYNOPSIS
        Best-effort map from a FortiGate service-GROUP name (e.g. "IKEv2_AS400_Services") to a set of
        catalogue service names. Anything it cannot resolve returns @('Ping') plus a TODO note upstream.
    #>
    param([string]$ServiceGroupName)
    $n = "$ServiceGroupName"
    $set = New-Object System.Collections.Generic.List[string]
    if ($n -match 'RDS|RDP|Remote *Desktop|PlantDT') { $set.Add('RDP') }
    if ($n -match 'AS400|iSeries|5250')             { $set.Add('RDP'); $set.Add('Telnet') }
    if ($n -match 'SMB|File|CIFS')                  { $set.Add('SMB') }
    if ($n -match 'DC|Domain|Kerb|LDAP')            { $set.Add('Kerberos'); $set.Add('LDAP') }
    if ($n -match 'DNS')                            { $set.Add('DNS') }
    if ($n -match 'Web|HTTP|Portal')               { $set.Add('HTTPS') }
    if ($n -match 'SIP|Phone|3CX|Voice')           { $set.Add('SIP'); $set.Add('HTTPS') }
    if ($n -match 'HVAC|SSH')                      { $set.Add('SSH') }
    if ($set.Count -eq 0) { $set.Add('Ping') }
    if (-not $set.Contains('Ping')) { $set.Add('Ping') }
    return ($set.ToArray() | Select-Object -Unique)
}

function Get-EvalServicesForLabelText {
    <# Infers services from a free-text endpoint label (used when folding in a User-UnitTests file). #>
    param([string]$Text)
    $n = "$Text"
    $set = New-Object System.Collections.Generic.List[string]
    if ($n -match '\bDC\b|Domain Controller') { 'DNS','Kerberos','LDAP','LDAPS','GlobalCat','DCE-RPC' | ForEach-Object { $set.Add($_) } }
    if ($n -match 'File ?Server|Fileshare|\bFS\b|SMB') { $set.Add('SMB'); $set.Add('Kerberos') }
    if ($n -match 'RDS|RDP|Remote Desktop') { $set.Add('RDP') }
    if ($n -match '3CX|Phone|SIP|Voice') { $set.Add('SIP'); $set.Add('HTTPS'); $set.Add('3CX-5001') }
    if ($n -match 'HVAC') { $set.Add('SSH'); $set.Add('Telnet'); $set.Add('HTTPS') }
    if ($n -match 'HMRS|MAS90|Util|MercyOne|ISDG|Houlihan|Sage') { $set.Add('RDP') }
    if ($set.Count -eq 0) { $set.Add('Ping'); $set.Add('RDP') }
    if (-not $set.Contains('Ping')) { $set.Add('Ping') }
    return ($set.ToArray() | Select-Object -Unique)
}

# --------------------------------------------------------------------------------------------------
# Reachability matrix
# --------------------------------------------------------------------------------------------------
function Invoke-EvalReachabilityMatrix {
    <#
    .SYNOPSIS
        Probes a list of endpoint objects (@{ Host; Name; Services=@(...); Expect='Allow'|'Block' })
        against the port catalogue and returns one result row per endpoint with a Verdict + Match.
    .PARAMETER ProbeOverride
        Test seam: scriptblock ($HostName, $Proto('tcp'|'udp'|'icmp'), $Port) -> [bool]. When supplied,
        no real sockets are opened.
    #>
    param(
        [Parameter(Mandatory)]$Endpoints,
        [Parameter(Mandatory)]$ServiceChecks,
        [int]$TimeoutMs = 500,
        [int]$PingTimeoutMs = 500,
        [scriptblock]$ProbeOverride
    )

    $probe = {
        param($HostName, $Proto, $Port)
        if ($ProbeOverride) { return [bool](& $ProbeOverride $HostName $Proto $Port) }
        switch ($Proto) {
            'icmp' { return Test-EvalPing   -ComputerName $HostName -TimeoutMs $PingTimeoutMs }
            'tcp'  { return Test-EvalTcpPort -ComputerName $HostName -Port $Port -TimeoutMs $TimeoutMs }
            'udp'  { return Test-EvalUdpPort -ComputerName $HostName -Port $Port -TimeoutMs $TimeoutMs }
        }
        return $false
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($ep in $Endpoints) {
        $epHost   = Get-EvalProp $ep 'Host'
        $epName   = Get-EvalProp $ep 'Name' $epHost
        $epExpect = Get-EvalProp $ep 'Expect' 'Allow'
        $epSvcs   = Get-EvalProp $ep 'Services' @('Ping')
        if (-not $epSvcs -or @($epSvcs).Count -eq 0) { $epSvcs = @('Ping') }

        $perSvc = [ordered]@{}
        $anyOpen = $false
        foreach ($svc in $epSvcs) {
            if ($svc -eq 'Ping') {
                $r = [bool](& $probe $epHost 'icmp' 0)
                $perSvc[$svc] = $r
                if ($r) { $anyOpen = $true }
                continue
            }
            $def = $ServiceChecks[$svc]
            if (-not $def) { $perSvc[$svc] = $null; continue }
            $results = @()
            foreach ($p in @(Get-EvalProp $def 'TCP' @())) { $results += [bool](& $probe $epHost 'tcp' $p) }
            foreach ($p in @(Get-EvalProp $def 'UDP' @())) { $results += [bool](& $probe $epHost 'udp' $p) }
            $svcOpen = if ($results.Count -eq 0) { $null } else { ($results -contains $true) }
            $perSvc[$svc] = $svcOpen
            if ($svcOpen -eq $true) { $anyOpen = $true }
        }

        $verdict = if ($anyOpen) { 'Allow' } else { 'Block' }
        $rows.Add([pscustomobject]@{
            Host       = $epHost
            Name       = $epName
            Expect     = $epExpect
            Verdict    = $verdict
            Match      = ($verdict -ieq $epExpect)
            PerService = $perSvc
        })
    }
    return $rows
}

# --------------------------------------------------------------------------------------------------
# Targets file I/O
# --------------------------------------------------------------------------------------------------
function Read-EvalTargets {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "Targets file not found: $Path" }
    if (Get-Command Import-PowerShellDataFile -ErrorAction SilentlyContinue) {
        return Import-PowerShellDataFile -Path $Path
    }
    $raw = Get-Content -Path $Path -Raw
    return (Invoke-Expression $raw)
}

function ConvertTo-EvalPsd1 {
    <# Minimal, safe .psd1 serializer: strings / ints / bools / $null / arrays / (ordered)hashtables. #>
    param([Parameter(Mandatory)][AllowNull()]$InputObject, [int]$Indent = 0)
    $pad = ' ' * ($Indent * 4)
    $pad2 = ' ' * (($Indent + 1) * 4)

    if ($null -eq $InputObject) { return '$null' }
    if ($InputObject -is [bool]) { return $(if ($InputObject) { '$true' } else { '$false' }) }
    if ($InputObject -is [int] -or $InputObject -is [long] -or $InputObject -is [double] -or $InputObject -is [decimal]) { return "$InputObject" }
    if ($InputObject -is [string]) { return "'" + ($InputObject -replace "'", "''") + "'" }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Count -eq 0) { return '@{}' }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('@{')
        foreach ($k in $InputObject.Keys) {
            $keyText = if ("$k" -match '^[A-Za-z_][A-Za-z0-9_]*$') { "$k" } else { "'" + ("$k" -replace "'", "''") + "'" }
            $valText = ConvertTo-EvalPsd1 -InputObject $InputObject[$k] -Indent ($Indent + 1)
            [void]$sb.AppendLine("$pad2$keyText = $valText")
        }
        [void]$sb.Append("$pad}")
        return $sb.ToString()
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        # NB: @($list) crashes the PS7 binder when the list holds IDictionary elements - collect by hand.
        $items = New-Object System.Collections.ArrayList
        foreach ($x in $InputObject) { [void]$items.Add($x) }
        if ($items.Count -eq 0) { return '@()' }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('@(')
        for ($i = 0; $i -lt $items.Count; $i++) {
            $valText = ConvertTo-EvalPsd1 -InputObject $items[$i] -Indent ($Indent + 1)
            $comma = if ($i -lt $items.Count - 1) { ',' } else { '' }
            [void]$sb.AppendLine("$pad2$valText$comma")
        }
        [void]$sb.Append("$pad)")
        return $sb.ToString()
    }

    return "'" + ("$InputObject" -replace "'", "''") + "'"
}

function ConvertFrom-UnitTestsFile {
    <#
    .SYNOPSIS
        Pulls the $Endpoints and $ServiceChecks literals out of a User-UnitTests-style .ps1 via AST
        (no execution of the rest of the file). Returns @{ Endpoints = [ordered]; ServiceChecks = [ordered] }.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $tokens = $null; $perr = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$perr)
    if ($perr.Count -gt 0) { throw "Parse errors in $Path" }

    $grab = {
        param($VarName)
        $node = $ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $n.Left.VariablePath.UserPath -eq $VarName
        }, $true) | Select-Object -First 1
        if (-not $node) { return $null }
        return (Invoke-Expression $node.Right.Extent.Text)
    }

    return @{
        Endpoints     = (& $grab 'Endpoints')
        ServiceChecks = (& $grab 'ServiceChecks')
    }
}
