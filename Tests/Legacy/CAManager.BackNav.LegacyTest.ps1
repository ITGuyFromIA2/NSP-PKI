# Ported from NSP-FGTIPSecTools Tests\CAManager.BackNav.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - back-navigation (2026-09-10, Part A item 3): Test-CABackSignal, the
    -AllowBack extension to Read-CANonEmpty / Get-CAAnswerOrPrompt, the new Read-CAOptional helper,
    and the generic Invoke-CAWizardSteps driver (CAInteractive.ps1) - plus source-introspection that
    the two rollout sites (menu 14 FortiGate handoff, menu 6's "6a" App Proxy prompts) actually use
    them.

    Reuses CLIBuilder's own established convention (a literal 'B'/'Back' input steps back one
    prompt), not a new idiom - see CLIBuilder's own $CanGoBack / $GoBack handling for the model this
    mirrors.

    Repo convention (Tests\README.md) - NOT Pester. A global `function Read-Host` mock reads from a
    FIFO queue (same pattern as CAManager.TestCertSuite.Tests.ps1).
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CAInteractive.ps1"      -Because "CAInteractive.ps1 parses after the back-nav primitives"
Test-ScriptParses -Path "$Mod\CAFortiGateHandoff.ps1" -Because "CAFortiGateHandoff.ps1 parses after the menu-14 back-nav rewrite"
Test-ScriptParses -Path $Dashboard                    -Because "CA-Manager.ps1 still parses"

. "$Mod\CACore.ps1"
. "$Mod\CAInteractive.ps1"
. "$Mod\CAFortiGateHandoff.ps1"

$script:__rhQ = [System.Collections.Generic.Queue[string]]::new()
function Read-Host { param([string]$Prompt, [switch]$AsSecureString) if ($script:__rhQ.Count -eq 0) { throw "Read-Host queue empty (prompt: '$Prompt')" } $script:__rhQ.Dequeue() }

# ---------------------------------------------------------------------------
# 1. Test-CABackSignal
# ---------------------------------------------------------------------------
Assert-True  -Condition (Test-CABackSignal $script:CABackSignal) -Because "the sentinel itself is recognised"
Assert-False -Condition (Test-CABackSignal 'B') -Because "the literal user input 'B' is NOT the sentinel - only what Read-CANonEmpty/Read-CAOptional return for it is"
Assert-False -Condition (Test-CABackSignal '') -Because "an empty string is not the sentinel"
Assert-False -Condition (Test-CABackSignal $null) -Because "`$null is not the sentinel"
Assert-False -Condition (Test-CABackSignal 123) -Because "a non-string is never the sentinel"

# ---------------------------------------------------------------------------
# 2. Read-CANonEmpty -AllowBack
# ---------------------------------------------------------------------------
$script:__rhQ.Enqueue('B')
$r = Read-CANonEmpty -Prompt "x" -AllowBack
Assert-True -Condition (Test-CABackSignal $r) -Because "'B' with -AllowBack returns the back sentinel"

$script:__rhQ.Enqueue('Back')
$r = Read-CANonEmpty -Prompt "x" -AllowBack
Assert-True -Condition (Test-CABackSignal $r) -Because "'Back' (the friendlier spelling) also triggers it"

$script:__rhQ.Enqueue('back')
$r = Read-CANonEmpty -Prompt "x" -AllowBack
Assert-True -Condition (Test-CABackSignal $r) -Because "case-insensitive"

$script:__rhQ.Enqueue('B')
$r = Read-CANonEmpty -Prompt "x"
Assert-Equal -Actual $r -Expected 'B' -Because "WITHOUT -AllowBack, a literal 'B' is just a normal (if odd) value - never mistaken for the sentinel"

$script:__rhQ.Enqueue('some real value')
$r = Read-CANonEmpty -Prompt "x" -AllowBack
Assert-Equal -Actual $r -Expected 'some real value' -Because "a normal answer still passes through untouched when -AllowBack is set but not triggered"

# ---------------------------------------------------------------------------
# 3. Read-CAOptional -AllowBack
# ---------------------------------------------------------------------------
$script:__rhQ.Enqueue('B')
$r = Read-CAOptional -Prompt "x" -AllowBack
Assert-True -Condition (Test-CABackSignal $r) -Because "Read-CAOptional recognises the same back convention"

$script:__rhQ.Enqueue('')
$r = Read-CAOptional -Prompt "x" -AllowBack
Assert-Equal -Actual $r -Expected '' -Because "blank is still a valid (empty) answer for an optional field, not a re-prompt"

$script:__rhQ.Enqueue('B')
$r = Read-CAOptional -Prompt "x"
Assert-Equal -Actual $r -Expected 'B' -Because "WITHOUT -AllowBack, Read-CAOptional also treats 'B' as a literal value"

# ---------------------------------------------------------------------------
# 4. Get-CAAnswerOrPrompt -AllowBack
# ---------------------------------------------------------------------------
$ans = [pscustomobject]@{}
$script:__rhQ.Enqueue('B')
$r = Get-CAAnswerOrPrompt -CAAnswers $ans -Field 'SomeField' -Prompt "x" -Remember -AllowBack
Assert-True  -Condition (Test-CABackSignal $r) -Because "Get-CAAnswerOrPrompt surfaces the back signal from its underlying Read-CANonEmpty call"
Assert-False -Condition ([bool]$ans.PSObject.Properties['SomeField']) -Because "a back signal is NEVER written back onto CAAnswers, even with -Remember"

$ans2 = [pscustomobject]@{ AlreadySet = 'existing-value' }
$r2 = Get-CAAnswerOrPrompt -CAAnswers $ans2 -Field 'AlreadySet' -Prompt "x" -Remember -AllowBack
Assert-Equal -Actual $r2 -Expected 'existing-value' -Because "an already-answered field short-circuits before any prompt - nothing to back out of, so it just returns the remembered value"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "the short-circuit never touches Read-Host at all"

$ans3 = [pscustomobject]@{}
$script:__rhQ.Enqueue('typed-value')
$r3 = Get-CAAnswerOrPrompt -CAAnswers $ans3 -Field 'NewField' -Prompt "x" -Remember -AllowBack
Assert-Equal -Actual $r3 -Expected 'typed-value' -Because "a normal answer still gets remembered when -AllowBack is set but not triggered"
Assert-Equal -Actual $ans3.NewField -Expected 'typed-value' -Because "and IS written back onto CAAnswers"

# ---------------------------------------------------------------------------
# 5. Invoke-CAWizardSteps - the generic driver
# ---------------------------------------------------------------------------
# Straight-through, no back at all
$order = New-Object System.Collections.Generic.List[string]
$steps = @(
    @{ Name = 'A'; Run = { param($CanGoBack) $order.Add("A:$CanGoBack"); 'valA' } }
    @{ Name = 'B'; Run = { param($CanGoBack) $order.Add("B:$CanGoBack"); 'valB' } }
    @{ Name = 'C'; Run = { param($CanGoBack) $order.Add("C:$CanGoBack"); 'valC' } }
)
$result = Invoke-CAWizardSteps -Steps $steps
Assert-Equal -Actual $result.A -Expected 'valA' -Because "step A's value lands in the result"
Assert-Equal -Actual $result.B -Expected 'valB' -Because "step B's value lands in the result"
Assert-Equal -Actual $result.C -Expected 'valC' -Because "step C's value lands in the result"
Assert-Equal -Actual ($order -join ',') -Expected 'A:False,B:True,C:True' -Because "CanGoBack is false only for the very first step - true for every step after it"

# One step-back, then proceed - re-runs the step it lands back on FROM SCRATCH (CLIBuilder's own
# "recompute fresh" convention, not a rewind to a remembered prior answer)
$order.Clear()
$bAttempt = 0
$steps2 = @(
    @{ Name = 'A'; Run = { param($CanGoBack) $order.Add("A:$CanGoBack"); 'valA' } }
    @{ Name = 'B'; Run = {
        param($CanGoBack)
        $script:bAttempt++
        $order.Add("B:${CanGoBack}:attempt${script:bAttempt}")
        if ($script:bAttempt -eq 1) { return $script:CABackSignal }   # go back to A once, then proceed
        'valB-second-try'
    } }
    @{ Name = 'C'; Run = { param($CanGoBack) $order.Add("C:$CanGoBack"); 'valC' } }
)
$result2 = Invoke-CAWizardSteps -Steps $steps2
Assert-Equal -Actual ($order -join '|') -Expected 'A:False|B:True:attempt1|A:False|B:True:attempt2|C:True' -Because "B's first attempt backs into A, which re-runs from scratch, then B is retried and this time proceeds"
Assert-Equal -Actual $result2.B -Expected 'valB-second-try' -Because "only the FINAL accepted value for B lands in the result - the aborted first attempt is discarded"

# Regression guard: a step backing out at index 0 must clamp to 0, not wrap to the LAST step
# (PowerShell arrays support negative indexing - $Steps[-1] would silently jump to the end)
$order.Clear()
$aAttempt = 0
$steps3 = @(
    @{ Name = 'Only'; Run = {
        param($CanGoBack)
        $script:aAttempt++
        $order.Add("Only:attempt$script:aAttempt")
        if ($script:aAttempt -eq 1) { return $script:CABackSignal }   # misbehaving step - backs out even though $CanGoBack was $false
        'valOnly'
    } }
    @{ Name = 'Never'; Run = { param($CanGoBack) $order.Add('Never-ran'); 'valNever' } }
)
$result3 = Invoke-CAWizardSteps -Steps $steps3
Assert-Equal -Actual ($order -join '|') -Expected 'Only:attempt1|Only:attempt2|Never-ran' -Because "backing out of index 0 clamps to 0 and retries 'Only' immediately (NOT wrapping to 'Never', which is the regression this guards) - 'Never' only runs afterward, once 'Only' legitimately succeeds and the driver advances past it"
Assert-Equal -Actual $result3.Only -Expected 'valOnly' -Because "the first step's eventual real value still lands in the result"
Assert-Equal -Actual $result3.Never -Expected 'valNever' -Because "and the second step does run normally once the first resolves"

# ---------------------------------------------------------------------------
# 6. Source-introspection - the two rollout sites actually use Invoke-CAWizardSteps
# ---------------------------------------------------------------------------
$srcHandoff = (Get-Command Invoke-CAMenuHandoff).Definition
Assert-Match -Actual $srcHandoff -Pattern 'Invoke-CAWizardSteps' -Because "menu 14's prompt-gathering sequence (company/cert-name/peer-name/peer-filter/fqdn/outdir/inpath) routes through the shared back-nav driver"
Assert-Match -Actual $srcHandoff -Pattern "-AllowBack:\`$CanGoBack" -Because "its steps actually thread `$CanGoBack into the back-aware prompt helpers, not just call them plain"

$srcAppProxy = (Get-Command Invoke-CAMenuAppProxy).Definition
Assert-Match -Actual $srcAppProxy -Pattern 'Invoke-CAWizardSteps' -Because "menu 6's '6a' trio (connector group / CRL app name / OCSP app name) also routes through it"
Assert-Match -Actual $srcAppProxy -Pattern "mutating action" -Because "the wizard documents WHY back-nav stops after 6a and isn't offered across the rest of the mutating steps"

Write-TestSummary -Suite "CA-Manager Back-Navigation"
