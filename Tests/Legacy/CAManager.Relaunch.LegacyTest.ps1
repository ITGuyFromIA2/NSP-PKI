# NSP.PKI: the dashboard-wiring checks (menu 1, R, U) expect the module's manifest path, no shim, the 'PKI Manager' name, and a Gallery update for U.
# Ported from NSP-FGTIPSecTools Tests\CAManager.Relaunch.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - "relaunch CA-Manager" (2026-09-11). The maintainer, live on Contoso-CA, ran menu 1
    (RSAT/management-module install), saw its existing "Re-launch CA-Manager so the new modules
    load." message, and asked for an actual relaunch OPTION instead of having to close the window and
    double-click the script by hand: "Can we have a 'relaunch CAManager' option from the dashboard /
    offered at the end of this?"

    Covers: the new shared Invoke-CAManagerRelaunch (CACore.ps1, mirrors the top-of-file self-elevate
    Start-Process/-Verb RunAs pattern, explicit -ScriptPath/-ShimPath/-CAConfigName - never reads its
    own $PSCommandPath, same reasoning ShimEngine.ps1 documents), Invoke-CAMenuPrereqs's new
    end-of-menu relaunch offer (only after a real, non-dry-run install attempt, only when a ScriptPath
    was actually given), and the dashboard's new standalone 'R' key.

    Repo convention (Tests\README.md) - NOT Pester. A global `function Read-Host` mock reads from a
    FIFO queue (same pattern as CAManager.AdHocTemplate.Tests.ps1 / CAManager.BackNav.Tests.ps1).
    Invoke-CAManagerRelaunch itself is never actually invoked for real in these tests (it calls
    Start-Process + exit) - it's either source-introspected, or shadowed by a same-named recording
    mock ("later definition wins") when testing Invoke-CAMenuPrereqs's decision to call it.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CACore.ps1"        -Because "CACore.ps1 parses after Invoke-CAManagerRelaunch"
Test-ScriptParses -Path "$Mod\CAInteractive.ps1" -Because "CAInteractive.ps1 parses after Invoke-CAMenuPrereqs's relaunch offer"
Test-ScriptParses -Path $Dashboard               -Because "CA-Manager.ps1 parses after wiring the 'R' key"

. "$Mod\CACore.ps1"
. "$Mod\CAInteractive.ps1"

$script:__rhQ = [System.Collections.Generic.Queue[string]]::new()
function Read-Host { param([string]$Prompt, [switch]$AsSecureString) if ($script:__rhQ.Count -eq 0) { throw "Read-Host queue empty (prompt: '$Prompt')" } $script:__rhQ.Dequeue() }

# ---------------------------------------------------------------------------
# 1. Invoke-CAManagerRelaunch - source shape only (calls Start-Process + exit for real)
# ---------------------------------------------------------------------------
$srcRelaunch = (Get-Command Invoke-CAManagerRelaunch).Definition
Assert-Match   -Actual $srcRelaunch -Pattern '\[Parameter\(Mandatory\)\]\[string\]\$ScriptPath' -Because "ScriptPath is required - no relaunch without knowing what to relaunch"
Assert-Match   -Actual $srcRelaunch -Pattern "'-NoProfile', '-ExecutionPolicy', 'Bypass', '-File'" -Because "mirrors CA-Manager.ps1's own top-of-file self-elevate relaunch args exactly"
Assert-Match   -Actual $srcRelaunch -Pattern "IsNullOrWhiteSpace\(\`$ShimPath\)" -Because "only adds -ShimPath to the relaunch args when one was actually given"
Assert-Match   -Actual $srcRelaunch -Pattern "\`$relaunchArgs \+= @\('-ShimPath'" -Because "threads ShimPath through to the relaunched process"
Assert-Match   -Actual $srcRelaunch -Pattern "IsNullOrWhiteSpace\(\`$CAConfigName\)" -Because "same guard for CAConfigName"
Assert-Match   -Actual $srcRelaunch -Pattern "\`$relaunchArgs \+= @\('-CAConfigName'" -Because "threads CAConfigName through to the relaunched process"
Assert-Match   -Actual $srcRelaunch -Pattern 'Start-Process powershell\.exe -ArgumentList \$relaunchArgs -Verb RunAs' -Because "relaunches elevated, same as the self-elevate block"
Assert-Match   -Actual $srcRelaunch -Pattern 'exit 0' -Because "ends the current session after starting the fresh one - never runs both at once"

# ---------------------------------------------------------------------------
# 2. Invoke-CAMenuPrereqs - functional: the new relaunch offer, mocking everything it calls
# ---------------------------------------------------------------------------
function Get-CAManagementPrereqStatus { [pscustomobject]@{ ActiveDirectory = $false; GroupPolicy = $false; GraphAuth = $true } }
$script:__installCalled = $false
function Install-CAManagementPrereqs { param([switch]$IncludeAdcsTools, [switch]$IncludeOcspTools) $script:__installCalled = $true }
$script:__relaunchCalled = $false
$script:__relaunchArgs = $null
function Invoke-CAManagerRelaunch { param([string]$ScriptPath, [string]$ShimPath, [string]$CAConfigName) $script:__relaunchCalled = $true; $script:__relaunchArgs = @{ ScriptPath = $ScriptPath; ShimPath = $ShimPath; CAConfigName = $CAConfigName } }

# 2a. Normal case: a real (non-dry-run) install happens, ScriptPath is given, tech says yes -> relaunches
Set-CADryRun -Enabled $false
$script:__installCalled = $false; $script:__relaunchCalled = $false; $script:__relaunchArgs = $null
$script:__rhQ.Enqueue('n')  # AD CS tools?
$script:__rhQ.Enqueue('n')  # Online Responder tools?
$script:__rhQ.Enqueue('y')  # Proceed?
$script:__rhQ.Enqueue('y')  # Relaunch CA-Manager now?
Invoke-CAMenuPrereqs -ScriptPath 'C:\fake\CA-Manager.ps1' -ShimPath 'C:\fake\Shim.ps1' -CAConfigName 'FakeCA'
Assert-True  -Condition $script:__installCalled   -Because "Proceed=y actually calls Install-CAManagementPrereqs"
Assert-True  -Condition $script:__relaunchCalled  -Because "a real install + non-dry-run + a ScriptPath + saying yes -> offers and then actually calls the relaunch"
Assert-Equal -Actual $script:__relaunchArgs.ScriptPath   -Expected 'C:\fake\CA-Manager.ps1' -Because "ScriptPath threads through to the relaunch call unchanged"
Assert-Equal -Actual $script:__relaunchArgs.ShimPath     -Expected 'C:\fake\Shim.ps1'        -Because "ShimPath threads through too"
Assert-Equal -Actual $script:__relaunchArgs.CAConfigName -Expected 'FakeCA'                  -Because "and CAConfigName"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "the function returns immediately after calling the relaunch - it never falls through to the trailing 'Press Enter to return' prompt"

# 2b. Tech declines the relaunch offer -> falls through to the normal 'Press Enter to return'
$script:__installCalled = $false; $script:__relaunchCalled = $false; $script:__relaunchArgs = $null
$script:__rhQ.Enqueue('n'); $script:__rhQ.Enqueue('n'); $script:__rhQ.Enqueue('y')  # adcs/ocsp/proceed
$script:__rhQ.Enqueue('n')  # Relaunch CA-Manager now? -> no
$script:__rhQ.Enqueue('')   # Press Enter to return to the menu
Invoke-CAMenuPrereqs -ScriptPath 'C:\fake\CA-Manager.ps1'
Assert-False -Condition $script:__relaunchCalled -Because "declining the offer never calls Invoke-CAManagerRelaunch"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "falls through to (and consumes) the trailing Press-Enter prompt instead"

# 2c. DRY RUN - the offer is never even asked, regardless of what "install" did
Set-CADryRun -Enabled $true
$script:__relaunchCalled = $false
$script:__rhQ.Enqueue('n'); $script:__rhQ.Enqueue('n'); $script:__rhQ.Enqueue('y')  # adcs/ocsp/proceed
$script:__rhQ.Enqueue('')   # Press Enter to return to the menu (no relaunch prompt consumed)
Invoke-CAMenuPrereqs -ScriptPath 'C:\fake\CA-Manager.ps1'
Assert-False -Condition $script:__relaunchCalled -Because "DRY RUN never actually installed anything real, so offering to relaunch would be misleading - skipped entirely"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "exactly 4 prompts consumed - no fifth 'relaunch?' prompt appeared"
Set-CADryRun -Enabled $false

# 2d. No -ScriptPath given (old call-site shape / caller has nothing to relaunch with) -> offer skipped too
$script:__relaunchCalled = $false
$script:__rhQ.Enqueue('n'); $script:__rhQ.Enqueue('n'); $script:__rhQ.Enqueue('y')  # adcs/ocsp/proceed
$script:__rhQ.Enqueue('')   # Press Enter to return to the menu
Invoke-CAMenuPrereqs
Assert-False -Condition $script:__relaunchCalled -Because "a blank/omitted ScriptPath means there's nothing to relaunch - the offer is skipped rather than calling Invoke-CAManagerRelaunch with a blank path"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "again exactly 4 prompts, no relaunch prompt appeared"

# ---------------------------------------------------------------------------
# 2e. 2026-09-11, per the maintainer's Y/N-defaults review: adcs/ocsp/Graph-install all now default Yes, and
# the disclaimer + Graph-Auth-before-Proceed reorder are real. Re-mock GraphAuth = $false so the Graph
# prompt is actually asked (it's skipped entirely when already present, same as before this change).
# ---------------------------------------------------------------------------
function Get-CAManagementPrereqStatus { [pscustomobject]@{ ActiveDirectory = $false; GroupPolicy = $false; GraphAuth = $false } }
$script:__graphInstallCalled = $false
function Install-CAGraphModule { $script:__graphInstallCalled = $true }

# Blank answers to everything now mean YES across the board (adcs/ocsp/Graph-install/Proceed) -
# functional proof the -DefaultYes flips actually work, not just present in source.
Set-CADryRun -Enabled $false
$script:__installCalled = $false; $script:__graphInstallCalled = $false
$script:__rhQ.Enqueue(''); $script:__rhQ.Enqueue('')            # adcs? / ocsp? - blank = Yes
$script:__rhQ.Enqueue('')                                       # Graph-Auth install? - blank = Yes (asked BEFORE Proceed - see below)
$script:__rhQ.Enqueue('')                                       # Proceed? - blank = Yes
$script:__rhQ.Enqueue('n')                                      # Relaunch CA-Manager now? - explicit no
$script:__rhQ.Enqueue('')                                       # Press Enter to return to the menu
Invoke-CAMenuPrereqs -ScriptPath 'C:\fake\CA-Manager.ps1'
Assert-True -Condition $script:__installCalled      -Because "blank ('Proceed?') now defaults to Yes and actually installs"
Assert-True -Condition $script:__graphInstallCalled -Because "blank ('Install Microsoft.Graph.Authentication now?') now defaults to Yes and actually installs Graph too"

# Order: the Graph-Auth question is asked BEFORE 'Proceed?' - answer Graph=Yes but Proceed=No, and
# confirm Graph still installs (independent of Proceed's answer, same as before this change - only
# the ON-SCREEN ORDER moved) while the RSAT install itself does not.
$script:__installCalled = $false; $script:__graphInstallCalled = $false
$script:__rhQ.Enqueue('n'); $script:__rhQ.Enqueue('n')   # adcs? / ocsp?
$script:__rhQ.Enqueue('y')                                # Graph-Auth install? -> yes
$script:__rhQ.Enqueue('n')                                # Proceed? -> no
$script:__rhQ.Enqueue('n')                                # Relaunch CA-Manager now? -> no (didInstall is true from Graph alone, so this prompt IS reached)
$script:__rhQ.Enqueue('')                                 # Press Enter to return to the menu
Invoke-CAMenuPrereqs -ScriptPath 'C:\fake\CA-Manager.ps1'
Assert-False -Condition $script:__installCalled      -Because "declining 'Proceed?' skips the RSAT install itself"
Assert-True  -Condition $script:__graphInstallCalled -Because "...but Graph-Auth still installs - it was decided independently, BEFORE 'Proceed?' was even asked"

$srcPrereqs = (Get-Command Invoke-CAMenuPrereqs).Definition
Assert-Match -Actual $srcPrereqs -Pattern 'Everything below defaults to Yes' -Because "the disclaimer the maintainer asked for is present, so a tech blank-Entering through these knows what's about to happen"
Assert-Match -Actual $srcPrereqs -Pattern "AD CS management tools \(certtmpl / pkiview\)\?`" -DefaultYes" -Because "the AD CS tools prompt now defaults to Yes"
Assert-Match -Actual $srcPrereqs -Pattern "Also install the Online Responder management tools\?`" -DefaultYes" -Because "the Online Responder tools prompt now defaults to Yes"
$graphIdx   = $srcPrereqs.IndexOf('Install Microsoft.Graph.Authentication (machine-wide) now?')
$proceedIdx = $srcPrereqs.IndexOf('"`nProceed?"')
Assert-True -Condition ($graphIdx -ge 0 -and $proceedIdx -ge 0 -and $graphIdx -lt $proceedIdx) -Because "the Graph-Auth question is now asked BEFORE 'Proceed?' - all 'what to install' choices are gathered up front, then one Proceed triggers everything"

# ---------------------------------------------------------------------------
# 3. Dashboard wiring
# ---------------------------------------------------------------------------
$rawDash = Get-Content -Path $Dashboard -Raw
Assert-Match -Actual $rawDash -Pattern "'\^1\`$'\s*\{\s*Invoke-CAMenuPrereqs -ScriptPath \`$manifestPath -CAConfigName \`$CAConfigName\s*\}" -Because "menu 1's call site passes its own script identity through, so the end-of-menu relaunch offer actually has somewhere to relaunch to"
Assert-Match -Actual $rawDash -Pattern "'\^\[Rr\]\`$'\s*\{[\s\S]{0,200}?Invoke-CAManagerRelaunch -ScriptPath \`$manifestPath -CAConfigName \`$CAConfigName" -Because "a standalone 'R' dashboard key relaunches CA-Manager any time, not just right after menu 1"
Assert-Match -Actual $rawDash -Pattern "'\^\[Rr\]\`$'\s*\{[\s\S]{0,200}?Read-CAConfirm -Prompt \`"Relaunch PKI Manager now\?\`"" -Because "the 'R' key confirms first - a stray keypress shouldn't kill the session"
Assert-Match -Actual $rawDash -Pattern 'Relaunch PKI Manager \(e\.g\. after installing new modules in menu 1\)' -Because "the 'R' option is listed in the on-screen menu, next to D/?/Q"

# ---------------------------------------------------------------------------
# 4. Invoke-CAManagerUpdate (2026-09-15) - re-runs the SHIM (not just this dashboard) so a tech
#    gets a genuine code update instead of relaunching the same stale extracted copy. Per the maintainer:
#    "can we add a 're-run CA-Manager update' option in the main menu?" - directly grew out of a
#    same-day live debugging session where he had to be told, each time, to go re-copy specific
#    fixed files onto his box by hand.
# ---------------------------------------------------------------------------
$srcUpdate = (Get-Command Invoke-CAManagerUpdate).Definition
Assert-Match -Actual $srcUpdate -Pattern '\[Parameter\(Mandatory\)\]\[string\]\$ShimPath' -Because "ShimPath is required - this function's whole purpose is re-running the shim"
Assert-Match -Actual $srcUpdate -Pattern 'IsNullOrWhiteSpace\(\$ShimPath\)\s*-or\s*-not\s*\(Test-Path \$ShimPath\)' -Because "refuses (throws) rather than silently no-op'ing when there's no real shim path to re-run - a standalone/dev run has nothing to update"
Assert-Match -Actual $srcUpdate -Pattern "'-File', .*\`$ShimPath" -Because "relaunches the SHIM script, not the dashboard"
# The actual CALL SHAPE, not a bare substring - this function's own doc-comment explains, in prose,
# WHY there's no -Verb RunAs here (mentioning those exact words), which a bare substring check would
# false-fail against.
Assert-NoMatch -Actual $srcUpdate -Pattern 'Start-Process powershell\.exe -ArgumentList @\([^\)]*\) -Verb RunAs' -Because "the actual relaunch call has no -Verb RunAs - this process is already elevated, and a child process of an elevated process inherits that elevation on Windows"
Assert-Match -Actual $srcUpdate -Pattern 'exit 0' -Because "ends the current session after starting the shim - never runs both at once"

# Functional, but only the FAILURE (throws-before-exit) path - same reasoning this file's own header
# gives for never actually invoking Invoke-CAManagerRelaunch "for real": a real 'exit 0' inside this
# function would kill the whole test process. The missing-ShimPath guard clause throws BEFORE ever
# reaching Start-Process/exit, so it's the one path safe to invoke directly; the actual
# relaunch/exit shape is covered by source-introspection above instead.
Invoke-Expression (Get-FunctionSource -Path "$Mod\CACore.ps1" -FunctionName 'Invoke-CAManagerUpdate')
$threwForMissingShim = $false
try { Invoke-CAManagerUpdate -ShimPath (Join-Path $env:TEMP "definitely_does_not_exist_$([guid]::NewGuid().ToString('N')).ps1") } catch { $threwForMissingShim = $true }
Assert-True -Condition $threwForMissingShim -Because "a ShimPath that doesn't exist on disk throws rather than silently proceeding to relaunch a phantom file"
Remove-Item function:Invoke-CAManagerUpdate -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 5. Dashboard wiring for the 'U' key
# ---------------------------------------------------------------------------
# NSP.PKI: U updates the module from the PowerShell Gallery (the zip-era U re-ran the staged shim to fetch CAManager.zip).
Assert-Match -Actual $rawDash -Pattern "'\^\[Uu\]\`$'\s*\{\s*Invoke-PKIModuleUpdate -CAConfigName \`$CAConfigName" -Because "U updates NSP.PKI from the Gallery"
Assert-Match -Actual $rawDash -Pattern "(?s)function Invoke-PKIModuleUpdate.*Find-Module -Name NSP\.PKI.*Read-CAConfirm.*Install-Module -Name NSP\.PKI.*Invoke-CAManagerRelaunch" -Because "checks the Gallery, confirms, installs, then relaunches"
Assert-Match -Actual $rawDash -Pattern "Could not reach the PowerShell Gallery" -Because "an offline box gets a clear message, not a crash"
Assert-Match -Actual $rawDash -Pattern "Update NSP\.PKI from the PowerShell Gallery" -Because "the U option is listed in the on-screen menu"

Write-TestSummary -Suite "CA-Manager Relaunch (menu 1 offer + dashboard 'R' key + 'U' update key)"
