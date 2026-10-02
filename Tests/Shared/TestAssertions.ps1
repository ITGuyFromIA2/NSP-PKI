#region Standalone
<#
.SYNOPSIS
    Shared assertion helpers for this repo's Tests\ folder - formalizes the "AST-extract a single
    function + mock Read-Host via a response queue + manual assertion counter" convention this codebase
    has used ad hoc, in disposable scratchpad scripts, throughout its history (e.g. 94 assertions for
    the multi-group cookie-cutter firewall work, 69 for the shared-modules picklist rebuild, 23 for the
    IKEv2 address-group prefill work) into one small, PERSISTENT, reusable module instead of retyping
    the same counter/PASS-FAIL printer from scratch every time.

.DESCRIPTION
    Deliberately NOT Pester. This machine only has Pester 3.4.0 available (the old in-box version that
    ships with Windows PowerShell 5.1 - `Should Be`, not the modern `Should -Be`), and this repo's own
    established convention already works well and is what every prior test pass in this project used:
    - Extract ONE function's source via AST (Get-FunctionSource below) rather than dot-sourcing a whole
      script - CLIBuilder/Helpers.ps1/etc. have real top-level side effects (Read-Host prompts,
      elevation checks, file I/O) that a test must never trigger for real.
    - Mock a dependency by defining a same-named function AFTER extracting/dot-sourcing the real one -
      the same "later definition wins" mechanism Helpers.ps1's own doc comment describes this codebase
      already relying on (see the "no duplicate embedded functions" convention).
    - Feed canned answers to Read-Host via a response-queue mock.
    Reinventing all of that as Pester Describe/Context/It blocks right now would be a bigger, unproven
    shift for no real benefit - this file just gives the existing style a permanent home.

.EXAMPLE
    # Top of a *.Tests.ps1 file in this folder:
    . "$PSScriptRoot\TestAssertions.ps1"
    Reset-TestCounters

    Assert-Equal -Actual $x -Expected $y -Because "does the thing"
    Assert-True  -Condition ($x -gt 0) -Because "is positive"

    Write-TestSummary -Suite "MySuite"   # prints pass/fail totals, exits 1 if anything failed

.NOTES
    Run every test file in this folder:
        Get-ChildItem "$PSScriptRoot\*.Tests.ps1" | ForEach-Object { & $_.FullName }
    Each *.Tests.ps1 is a standalone, directly-runnable script (not a Pester-discovered file) - dot-
    source this file, run its own assertions, call Write-TestSummary once at the end.
#>

$script:TestPassCount = 0
$script:TestFailCount = 0
$script:TestFailures  = [System.Collections.Generic.List[string]]::new()

function Reset-TestCounters {
    <#
    .SYNOPSIS
        Call once at the top of each *.Tests.ps1 file so counts/failure messages don't bleed across
        files/suites run in the same session.
    #>
    $script:TestPassCount = 0
    $script:TestFailCount = 0
    $script:TestFailures  = [System.Collections.Generic.List[string]]::new()
}

function Write-AssertResult {
    param([bool]$Pass, [string]$Message)
    if ($Pass) {
        $script:TestPassCount++
        Write-Host "  PASS: $Message" -ForegroundColor Green
    } else {
        $script:TestFailCount++
        $script:TestFailures.Add($Message)
        Write-Host "  FAIL: $Message" -ForegroundColor Red
    }
}

function Assert-Equal {
    # -Actual/-Expected deliberately NOT [Parameter(Mandatory)] - same class of PowerShell gotcha
    # already documented elsewhere in this file (Use-QueuedReadHost's -Responses, Invoke-Step9Region's
    # -CustomAppRules): a Mandatory, untyped parameter rejects an explicit $null argument outright
    # ("Cannot bind argument... because it is null"), and asserting "this really is null" is a
    # completely normal, expected thing to test here.
    param($Actual, $Expected, [Parameter(Mandatory)][string]$Because)
    $pass = ($Actual -eq $Expected) -or ($null -eq $Actual -and $null -eq $Expected)
    Write-AssertResult -Pass $pass -Message "$Because (expected '$Expected', got '$Actual')"
}

function Assert-NotEqual {
    param($Actual, $NotExpected, [Parameter(Mandatory)][string]$Because)
    Write-AssertResult -Pass (-not ($Actual -eq $NotExpected)) -Message "$Because (expected NOT '$NotExpected', got '$Actual')"
}

function Assert-True {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Because)
    Write-AssertResult -Pass $Condition -Message $Because
}

function Assert-False {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Because)
    Write-AssertResult -Pass (-not $Condition) -Message $Because
}

function Assert-Match {
    param([Parameter(Mandatory)][string]$Actual, [Parameter(Mandatory)][string]$Pattern, [Parameter(Mandatory)][string]$Because)
    Write-AssertResult -Pass ($Actual -match $Pattern) -Message "$Because (pattern '$Pattern')"
}

function Assert-NoMatch {
    param([Parameter(Mandatory)][string]$Actual, [Parameter(Mandatory)][string]$Pattern, [Parameter(Mandatory)][string]$Because)
    Write-AssertResult -Pass ($Actual -notmatch $Pattern) -Message "$Because (pattern '$Pattern' should NOT match)"
}

function Assert-Contains {
    param([Parameter(Mandatory)][string]$Haystack, [Parameter(Mandatory)][string]$Needle, [Parameter(Mandatory)][string]$Because)
    Write-AssertResult -Pass ($Haystack -like "*$Needle*") -Message "$Because (expected to find: $Needle)"
}

function Assert-NotContains {
    param([Parameter(Mandatory)][string]$Haystack, [Parameter(Mandatory)][string]$Needle, [Parameter(Mandatory)][string]$Because)
    Write-AssertResult -Pass ($Haystack -notlike "*$Needle*") -Message "$Because (expected NOT to find: $Needle)"
}

function Get-ScriptRegionSource {
    <#
    .SYNOPSIS
        Extracts a chunk of source text between two anchor lines - for the (common in this codebase)
        case of testing a piece of INLINE top-level script logic that isn't wrapped in its own function
        (e.g. CLIBuilder's own `$replGroups`-building steps). Text-based (first line matching
        -StartPattern through the first line AT OR AFTER it matching -EndPattern, inclusive of both),
        not AST-based, since there's no function node to anchor to. Throws loudly if either anchor
        isn't found, or if -EndPattern is never seen after -StartPattern - same "loud failure beats
        silently testing nothing" reasoning as Get-FunctionSource below.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$StartPattern, [Parameter(Mandatory)][string]$EndPattern)

    $lines = Get-Content -Path $Path
    $startIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match $StartPattern) { $startIdx = $i; break } }
    if ($startIdx -lt 0) { throw "Start pattern '$StartPattern' not found in $Path" }
    $endIdx = -1
    for ($i = $startIdx; $i -lt $lines.Count; $i++) { if ($lines[$i] -match $EndPattern) { $endIdx = $i; break } }
    if ($endIdx -lt 0) { throw "End pattern '$EndPattern' not found in $Path (after line $($startIdx + 1))" }
    # CRLF, not bare LF - this repo is CRLF throughout (see the "CRLF line-ending discipline" project
    # convention), and Get-Content strips whatever line ending was there, so anything comparing this
    # extracted text's OWN embedded heredocs against a literal heredoc written directly in a *.Tests.ps1
    # file needs both sides using the same line ending or Assert-Equal fails on an invisible mismatch.
    return ($lines[$startIdx..$endIdx] -join "`r`n")
}

function Get-FunctionSource {
    <#
    .SYNOPSIS
        Extracts ONE function's source text out of a larger .ps1 file via AST, without dot-sourcing (or
        otherwise executing) the rest of that file. Throws loudly if the function name isn't found - a
        test that silently tests nothing (e.g. because the real function got renamed) is worse than a
        loud failure.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$FunctionName)

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw "Parse errors in $Path - fix before extracting functions from it:`n$($parseErrors | Out-String)"
    }
    $funcAst = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $FunctionName }, $true) |
        Select-Object -First 1
    if (-not $funcAst) {
        throw "Function '$FunctionName' not found in $Path - has it been renamed or removed?"
    }
    return $funcAst.Extent.Text
}

function Test-ScriptParses {
    <#
    .SYNOPSIS
        Cheap parse-only smoke test for a whole .ps1 file - wraps the same
        [System.Management.Automation.Language.Parser]::ParseFile pattern used everywhere else in this
        repo's build/push scripts (Build-And-Push-FCTZip.ps1 etc.) into one assertion call.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Because)
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors) | Out-Null
    $pass = ($parseErrors.Count -eq 0)
    $detail = if ($pass) { "" } else { " - $($parseErrors | Out-String)" }
    Write-AssertResult -Pass $pass -Message "$Because$detail"
}

function Use-QueuedReadHost {
    <#
    .SYNOPSIS
        Replaces Read-Host, for the rest of the current session, with a mock that returns the next
        queued response on each call - the standard way this codebase's tests script an entire
        interactive prompt sequence without a human at the keyboard. Defines a GLOBAL function, same
        "later definition wins" mechanism Helpers.ps1's own doc comment describes this codebase already
        relying on to shadow a real function for testing.
    .PARAMETER Responses
        Queued in call order. Throws loudly if the code under test calls Read-Host more times than
        responses were queued, rather than hanging or silently returning $null - that means the test's
        assumption about how many prompts the real code asks is wrong and needs fixing, not working
        around.

        NOT marked [Parameter(Mandatory)] - found live (2026-08-21) that PowerShell's automatic
        mandatory-parameter validation rejects an ENTIRE [string[]] argument if ANY single element in
        it is an empty string (not just if the whole array is null/empty) - and a blank response
        ("blank to keep current", "blank to finish") is completely normal and common to queue here.
        Validated manually instead (below) so a genuinely missing/null argument still fails loudly,
        without that surprising per-element rejection.
    #>
    param([string[]]$Responses)
    if ($null -eq $Responses) { throw "Use-QueuedReadHost: -Responses is required (pass an empty array @() if the code under test makes zero Read-Host calls)." }
    $script:__ReadHostQueue = [System.Collections.Generic.Queue[string]]::new([string[]]$Responses)
    function global:Read-Host {
        param([string]$Prompt)
        if ($script:__ReadHostQueue.Count -eq 0) { throw "Read-Host mock ran out of queued responses (prompt was: '$Prompt')" }
        return $script:__ReadHostQueue.Dequeue()
    }
}

function Restore-RealReadHost {
    <#
    .SYNOPSIS
        Removes the Use-QueuedReadHost mock so later code (or a later test file run in the same
        session via Run-AllTests.ps1) gets PowerShell's real Read-Host back, not a leftover mock stuck
        returning stale/exhausted queued responses.
    #>
    if (Get-Item -Path function:global:Read-Host -ErrorAction SilentlyContinue) { Remove-Item -Path function:global:Read-Host -ErrorAction SilentlyContinue }
}

function Write-TestSummary {
    param([Parameter(Mandatory)][string]$Suite)
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    $total = $script:TestPassCount + $script:TestFailCount
    $color = if ($script:TestFailCount -eq 0) { "Green" } else { "Red" }
    Write-Host "  $Suite`: $($script:TestPassCount)/$total assertions passed" -ForegroundColor $color
    if ($script:TestFailCount -gt 0) {
        Write-Host "  Failures:" -ForegroundColor Red
        foreach ($f in $script:TestFailures) { Write-Host "    - $f" -ForegroundColor Red }
    }
    Write-Host "================================================" -ForegroundColor Cyan
    # Explicit exit 0 on success, not just "don't exit 1" - found live (2026-08-21) that a *.Tests.ps1
    # invoked via Run-AllTests.ps1's `& $file.FullName` otherwise finishes with whatever $LASTEXITCODE
    # was left over from some earlier native/non-terminating call inside the test file (stale, not
    # necessarily 0), making Run-AllTests.ps1 misreport an all-green suite as failed.
    if ($script:TestFailCount -gt 0) { exit 1 } else { exit 0 }
}
#endregion Standalone
