<#
.SYNOPSIS
    Shared, tool-agnostic DRY RUN engine - extracted from CA-Manager's own Modules\CACore.ps1
    (2026-09-10, Part A item 9: "this is a great piece of functionality to have. Modularize it?").
    Every mutating action in a tool that dot-sources this file routes through Invoke-CAStep, which
    just prints the plan and does nothing while $script:CADryRun is $true - so an entire wizard can
    be walked end-to-end on any machine with zero side effects, then re-run for real once reviewed.

.DESCRIPTION
    Deliberately just MOVED here, not renamed - Invoke-CAStep/Get-CADryRun/Set-CADryRun keep their
    CA-prefixed names (a cosmetic wart for a "shared" file, not a functional one) so every existing
    CA-Manager call site across every Modules\CA*.ps1 file and every test keeps working completely
    unchanged; only WHERE the three functions live moved, not their names or behavior. Renaming them
    to something tool-neutral is real, separate future work if/when NPS Manager (which has no
    dry-run today) or a future GPO Manager actually adopts this file - not done here to keep this
    extraction itself a zero-ripple, purely mechanical move.

    CACore.ps1 dot-sources this file (see its own header) rather than defining these three functions
    itself now - same "locate one of a couple of candidate paths" pattern already proven by
    Modules\CATestSuite.ps1's own Request-VPNCertCore.ps1 lookup: a zip-layout candidate (this file
    bundled next to CA-Manager.ps1 by Build-CAManagerZip.ps1) and a repo-layout candidate (this file
    read directly from IPSEC AIO\MiscTools\Shared\ while developing/testing in the repo).
#>

# ---------------------------------------------------------------------------
# DRY RUN - every mutating engine (CAInstall / CATemplates / CAAutoEnrollGPO / CAUrls / ...) runs its
# real work through Invoke-CAStep. When $script:CADryRun is $true it prints exactly what it WOULD do
# and runs nothing; otherwise it prints the same "would do" summary, runs the action, and reports the
# outcome. The dashboard sets $script:CADryRun from a top-of-session prompt (and lets a tech toggle
# it), so every wizard can be walked end-to-end on any machine with zero side effects.
# ---------------------------------------------------------------------------
$script:CADryRun = $true

function Set-CADryRun {
    param([Parameter(Mandatory)][bool]$Enabled)
    $script:CADryRun = $Enabled
}
function Get-CADryRun { return [bool]$script:CADryRun }

function Invoke-CAStep {
    <#
    .SYNOPSIS
        Runs one mutating step, or (in dry-run) just describes it. Returns a result object:
        [pscustomobject]@{ Ran = <bool>; Description; Commands = @(...); Output; Error }.

    .PARAMETER Description
        One-line human summary ("Publish the auto-enroll GPO 'NSP - Certificate Auto-Enrollment'").

    .PARAMETER Commands
        The literal command(s) this step would run, as strings, for the dry-run preview and the
        transcript. Illustrative - not necessarily re-executable verbatim.

    .PARAMETER Action
        Scriptblock that performs the real work. Only invoked when not in dry-run. Its output is
        captured into .Output; a throw is caught into .Error and (unless -ContinueOnError) re-thrown.
    #>
    param(
        [Parameter(Mandatory)][string]$Description,
        [string[]]$Commands = @(),
        [Parameter(Mandatory)][scriptblock]$Action,
        [switch]$ContinueOnError
    )

    $dry = Get-CADryRun
    Write-Host ""
    Write-Host ("  {0} {1}" -f $(if ($dry) { '[DRY RUN]' } else { '[APPLY]  ' }), $Description) -ForegroundColor $(if ($dry) { 'Cyan' } else { 'Yellow' })
    foreach ($c in $Commands) { Write-Host "      $c" -ForegroundColor DarkGray }

    $res = [pscustomobject]@{ Ran = $false; Description = $Description; Commands = $Commands; Output = $null; Error = $null }
    if ($dry) { return $res }

    try {
        $res.Output = & $Action
        $res.Ran = $true
        Write-Host "      -> done" -ForegroundColor Green
    } catch {
        $res.Error = $_.Exception.Message
        Write-Host "      -> ERROR: $($res.Error)" -ForegroundColor Red
        if (-not $ContinueOnError) { throw }
    }
    return $res
}
