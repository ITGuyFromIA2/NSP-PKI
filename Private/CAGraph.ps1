<#
.SYNOPSIS
    CA Manager - Microsoft Graph connect + request helpers, shared by the App Proxy wizard
    (Modules\CAAppProxy.ps1, dashboard menu 6). Requires Modules\CACore.ps1 (Invoke-CAStep) and the
    Microsoft.Graph.Authentication module.

.DESCRIPTION
    These are ports of the read helpers already built and debugged in
    PushableTools\CAManager\Get-CAManagerEntraProxyInventory.ps1 (which stays a standalone script -
    it has to run BEFORE this tool exists). Behaviour is identical, including:
      - Invoke-CAGraph uses -SkipHttpErrorCheck / -StatusCodeVariable when the module build has them,
        so an expected 404/400 does not dump a full HTTP error block.
      - Get-CAGraphAll follows @odata.nextLink and ENUMERATES its result; it must NOT `,$items`-wrap
        (a piped wrapper unrolls and the downstream cmdlet gets the whole inner array as one item).
      - App Proxy endpoints (onPremisesPublishingProfiles/applicationProxy/*) and the full
        onPremisesPublishing object on applications live ONLY under /beta.

    Invoke-CAGraphStep is the WRITE path: it wraps a POST/PATCH/PUT/DELETE in Invoke-CAStep so every
    mutation is dry-run aware. Plain GET reads do NOT go through Invoke-CAStep - they are
    non-mutating and must run even in DRY RUN so the plan preview reflects the real tenant (same
    principle as CATemplates doing a live [ADSI]::Exists in dry-run).
#>

$script:CAGraphV1   = 'https://graph.microsoft.com/v1.0'
$script:CAGraphBeta  = 'https://graph.microsoft.com/beta'
$script:CAGraphCanSkipErr = $null   # resolved lazily on first call

# ---------------------------------------------------------------------------
function Repair-CAModulePath {
    <#
    .SYNOPSIS
        Ensures the standard per-user + AllUsers module directories are on $env:PSModulePath. The
        Entra private-network connector installer (run by menu 6 itself) rewrites PSModulePath and
        drops the CurrentUser path, which then hides an otherwise-installed Microsoft.Graph.Authentication.
    .NOTES
        Rebuilds PSModulePath from scratch out of Test-Path-VALIDATED directories rather than trusting
        the inherited string's own delimiters. Found live 2026-09-10 on a client's CA server: the inherited
        $env:PSModulePath had two entries glued together with no ';' between them (module name
        auto-discovery - Import-Module PowerShellGet by name - then fails with "no valid module file
        was found in any module directory" even though the real directory is right there on disk and a
        direct-path Import-Module succeeds). The old version only string-matched -notin against a
        naive -split ';' and would happily leave a malformed/garbage entry in place; this one keeps
        only entries that are real, existing directories, so a corrupted segment is silently dropped
        instead of propagated forward on every relaunch.
    #>
    $want = @(
        (Join-Path $HOME 'Documents\WindowsPowerShell\Modules')
        (Join-Path $HOME 'Documents\PowerShell\Modules')
        (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
        # the system dir - ServerManager / ADCSDeployment / ADCSAdministration live here. Should
        # never be absent, but the Entra connector installer rewrites the persistent PSModulePath
        # env var and an elevated relaunch can inherit a version that's missing it.
        (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\Modules')
    ) | ForEach-Object { $_.TrimEnd('\') }

    $existing = @($env:PSModulePath -split ';' |
        ForEach-Object { $_.Trim().TrimEnd('\') } |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container -ErrorAction SilentlyContinue) })

    $env:PSModulePath = (@($want + $existing) | Select-Object -Unique) -join ';'
}

function Connect-CAGraph {
    <#
    .SYNOPSIS
        Interactive Connect-MgGraph with the write scopes menu 6 needs. Returns Get-MgContext, or
        $null if the module is missing / sign-in failed.
    #>
    param(
        [string[]]$Scopes = @('Application.ReadWrite.All', 'Directory.ReadWrite.All', 'OnPremisesPublishingProfiles.ReadWrite.All'),
        [string]$TenantId
    )

    Repair-CAModulePath
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host "  Microsoft.Graph.Authentication is not installed - attempting to install it now..." -ForegroundColor Yellow
        if (Get-Command Install-CAGraphModule -ErrorAction SilentlyContinue) { Install-CAGraphModule }
        Repair-CAModulePath
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
            Write-Host "  Still not available. Install it manually (see the note above), then re-run menu 6." -ForegroundColor Red
            return $null
        }
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $connectArgs = @{ Scopes = $Scopes }
    if ($TenantId) { $connectArgs.TenantId = $TenantId }
    try {
        $connectArgs.NoWelcome = $true
        Connect-MgGraph @connectArgs -ErrorAction Stop
    } catch {
        # older module builds have no -NoWelcome
        [void]$connectArgs.Remove('NoWelcome')
        try { Connect-MgGraph @connectArgs -ErrorAction Stop }
        catch {
            Write-Host "  Graph sign-in failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    return (Get-MgContext)
}

# ---------------------------------------------------------------------------
function Invoke-CAGraph {
    <#
    .SYNOPSIS
        One Graph request. Returns [pscustomobject]@{ ok; status; body }. Never throws on an HTTP
        error - the caller inspects .ok / .status.
    #>
    param(
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')][string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri,
        $Body
    )
    if ($null -eq $script:CAGraphCanSkipErr) {
        $script:CAGraphCanSkipErr = (Get-Command Invoke-MgGraphRequest).Parameters.ContainsKey('SkipHttpErrorCheck')
    }

    $reqArgs = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) {
        $reqArgs.Body = if ($Body -is [string]) { $Body } else { ($Body | ConvertTo-Json -Depth 12 -Compress) }
        $reqArgs.ContentType = 'application/json'
    }

    if ($script:CAGraphCanSkipErr) {
        $sc = $null
        $b = Invoke-MgGraphRequest @reqArgs -SkipHttpErrorCheck -StatusCodeVariable sc -ErrorAction SilentlyContinue
        return [pscustomobject]@{ ok = ($sc -ge 200 -and $sc -lt 300); status = $sc; body = $b }
    }
    try {
        $b = Invoke-MgGraphRequest @reqArgs -ErrorAction Stop
        return [pscustomobject]@{ ok = $true; status = 200; body = $b }
    } catch {
        $code = $null; try { $code = [int]$_.Exception.Response.StatusCode.value__ } catch { }
        return [pscustomobject]@{ ok = $false; status = $code; body = $null }
    }
}

# ---------------------------------------------------------------------------
function Get-CAGraphAll {
    <#
    .SYNOPSIS
        GET a collection, following @odata.nextLink. ENUMERATES the flattened .value set - call sites
        wrap in @() when they need a guaranteed array. Do NOT `,$items`-wrap here.
    #>
    param([Parameter(Mandatory)][string]$Uri, [switch]$Quiet)
    $items = @(); $next = $Uri
    while ($next) {
        $res = Invoke-CAGraph -Method GET -Uri $next
        if (-not $res.ok) { if (-not $Quiet) { Write-Host "  (skip) $next -> HTTP $($res.status)" -ForegroundColor DarkYellow }; break }
        $b = $res.body
        if ($null -ne $b.value) { $items += $b.value } elseif ($b) { $items += $b }
        $next = $b.'@odata.nextLink'
    }
    $items
}

# ---------------------------------------------------------------------------
function Get-CAGraphOne {
    <#
    .SYNOPSIS
        GET a single resource. Returns the body, or $null on any HTTP error.
    #>
    param([Parameter(Mandatory)][string]$Uri, [switch]$Quiet)
    $res = Invoke-CAGraph -Method GET -Uri $Uri
    if ($res.ok) { return $res.body }
    if (-not $Quiet) { Write-Host "  (skip) $Uri -> HTTP $($res.status)" -ForegroundColor DarkYellow }
    return $null
}

# ---------------------------------------------------------------------------
function Invoke-CAGraphStep {
    <#
    .SYNOPSIS
        A MUTATING Graph call (POST/PATCH/PUT/DELETE) routed through Invoke-CAStep so it is dry-run
        aware. In DRY RUN it prints "<METHOD> <uri>" + the compact JSON body and returns $null. In
        APPLY it performs the call and THROWS on any non-2xx (so a Graph failure does not slip past
        Invoke-CAStep's "didn't throw == done"). Returns the response body.
    #>
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][ValidateSet('POST', 'PATCH', 'PUT', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        $Body
    )
    $jsonPreview = if ($null -ne $Body) { if ($Body -is [string]) { $Body } else { ($Body | ConvertTo-Json -Depth 12 -Compress) } } else { '(no body)' }
    $res = Invoke-CAStep -Description $Description `
        -Commands @("$Method $Uri", "  $jsonPreview") `
        -Action {
            $r = Invoke-CAGraph -Method $Method -Uri $Uri -Body $Body
            if (-not $r.ok) {
                $detail = try { $r.body | ConvertTo-Json -Depth 6 -Compress } catch { '' }
                throw "Graph $Method $Uri -> HTTP $($r.status) $detail"
            }
            $r.body
        }
    return $res.Output
}

# ---------------------------------------------------------------------------
function Get-CAGraphTenantInitialDomain {
    <#
    .SYNOPSIS
        The tenant's initial *.onmicrosoft.com domain LABEL (e.g. 'contoso' from
        'contoso.onmicrosoft.com'), used to compose the App Proxy hostnames. $null if unavailable.
    #>
    $org = Get-CAGraphOne "$script:CAGraphV1/organization?`$select=verifiedDomains"
    if (-not $org) { return $null }
    $row = @($org.value)[0]
    if (-not $row) { return $null }
    $initial = $row.verifiedDomains | Where-Object { $_.isInitial } | Select-Object -First 1
    if (-not $initial) { $initial = $row.verifiedDomains | Where-Object { $_.name -match '(?i)\.onmicrosoft\.com$' } | Select-Object -First 1 }
    if (-not $initial) { return $null }
    return ($initial.name -replace '(?i)\.onmicrosoft\.com$', '')
}

# ---------------------------------------------------------------------------
function Test-CAGraphWriteScopes {
    <#
    .SYNOPSIS
        Returns the required write scopes that the current Graph session is MISSING (empty == all present).
    #>
    param(
        [string[]]$Required = @('Application.ReadWrite.All', 'Directory.ReadWrite.All', 'OnPremisesPublishingProfiles.ReadWrite.All')
    )
    $have = @()
    try { $have = @((Get-MgContext).Scopes) } catch { }
    return @($Required | Where-Object { $_ -notin $have })
}
