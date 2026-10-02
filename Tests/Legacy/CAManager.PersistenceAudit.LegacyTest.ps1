# NSP.PKI: the centralized-save pattern allows the deeper indentation inside Start-NSPPkiManager.
# Ported from NSP-FGTIPSecTools Tests\CAManager.PersistenceAudit.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager - the answer-persistence audit (2026-09-10, Part A item 4):
    Get-CAAnswerOrPromptOptional (CAInteractive.ps1), the centralized once-per-menu-item
    Save-CAAnswers call in CA-Manager.ps1's dispatcher (replacing the old per-case opt-in), and
    that menu 4's umbrella-group / OCSP-responder-host prompts now share persisted fields instead
    of bare, unremembered Read-Host calls.

    Repo convention (Tests\README.md) - NOT Pester. A global `function Read-Host` mock reads from a
    FIFO queue (same pattern as CAManager.TestCertSuite.Tests.ps1 / CAManager.BackNav.Tests.ps1).
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"
$Dashboard = "$PKIModuleRoot\Tests\Legacy\_CA-Manager.combined.ps1"

Test-ScriptParses -Path "$Mod\CAInteractive.ps1" -Because "CAInteractive.ps1 parses after Get-CAAnswerOrPromptOptional"
Test-ScriptParses -Path $Dashboard               -Because "CA-Manager.ps1 parses after the centralized-save rewrite"

. "$Mod\CACore.ps1"
. "$Mod\CAInteractive.ps1"

$script:__rhQ = [System.Collections.Generic.Queue[string]]::new()
function Read-Host { param([string]$Prompt, [switch]$AsSecureString) if ($script:__rhQ.Count -eq 0) { throw "Read-Host queue empty (prompt: '$Prompt')" } $script:__rhQ.Dequeue() }

# ---------------------------------------------------------------------------
# 1. Get-CAAnswerOrPromptOptional - blank is a real, non-retried answer; non-blank gets remembered
# ---------------------------------------------------------------------------
$ans = [pscustomobject]@{}
$script:__rhQ.Enqueue('')
$r = Get-CAAnswerOrPromptOptional -CAAnswers $ans -Field 'CA_AutoEnrollGroup' -Prompt "x"
Assert-Equal -Actual $r -Expected '' -Because "a blank answer is accepted immediately - no 'value is required' retry loop, unlike Get-CAAnswerOrPrompt"
Assert-False -Condition ([bool]$ans.PSObject.Properties['CA_AutoEnrollGroup']) -Because "a blank answer is NOT remembered - the 'skip for now' promise means it asks again next time, not 'never configure this'"

$ans2 = [pscustomobject]@{}
$script:__rhQ.Enqueue('DOMAIN\Umbrella_Group')
$r2 = Get-CAAnswerOrPromptOptional -CAAnswers $ans2 -Field 'CA_AutoEnrollGroup' -Prompt "x"
Assert-Equal -Actual $r2 -Expected 'DOMAIN\Umbrella_Group' -Because "a real answer is returned"
Assert-Equal -Actual $ans2.CA_AutoEnrollGroup -Expected 'DOMAIN\Umbrella_Group' -Because "and IS remembered onto CAAnswers"

$ans3 = [pscustomobject]@{ CA_AutoEnrollGroup = 'AlreadyAnswered_Group' }
$r3 = Get-CAAnswerOrPromptOptional -CAAnswers $ans3 -Field 'CA_AutoEnrollGroup' -Prompt "x"
Assert-Equal -Actual $r3 -Expected 'AlreadyAnswered_Group' -Because "an already-remembered non-blank value short-circuits before any prompt"
Assert-Equal -Actual $script:__rhQ.Count -Expected 0 -Because "the short-circuit never touches Read-Host"

# -AllowBack still works the same way as Get-CAAnswerOrPrompt's
$ans4 = [pscustomobject]@{}
$script:__rhQ.Enqueue('B')
$r4 = Get-CAAnswerOrPromptOptional -CAAnswers $ans4 -Field 'CA_OcspResponderHost' -Prompt "x" -AllowBack
Assert-True  -Condition (Test-CABackSignal $r4) -Because "Get-CAAnswerOrPromptOptional surfaces the back signal too"
Assert-False -Condition ([bool]$ans4.PSObject.Properties['CA_OcspResponderHost']) -Because "a back signal is never remembered either"

# ---------------------------------------------------------------------------
# 2. Invoke-CAMenuTemplates - the two prompts that used to be bare, unremembered Read-Host calls
# ---------------------------------------------------------------------------
$srcMenu4 = (Get-Command Invoke-CAMenuTemplates).Definition
Assert-Match -Actual $srcMenu4 -Pattern "Get-CAAnswerOrPromptOptional -CAAnswers \`$CAAnswers -Field 'CA_AutoEnrollGroup'" -Because "the umbrella-group prompt is now remembered, not a bare Read-Host"
Assert-Match -Actual $srcMenu4 -Pattern "Get-CAAnswerOrPromptOptional -CAAnswers \`$CAAnswers -Field 'CA_OcspResponderHost'" -Because "the OCSP-responder-host prompt is now remembered under the SAME field the enrollment gate (menu 15) reads"
# 2026-09-11, per the maintainer's Y/N-defaults review ("what harm is it changing this to default Y? We
# re-imported many times over the top when testing") - confirmed safe: New-CAVpnTemplate already
# checks [ADSI]::Exists first and just skips a complete, already-existing template rather than
# erroring/duplicating - genuinely idempotent.
Assert-Match -Actual $srcMenu4 -Pattern 'Create/publish the \$\(\$selectedSpec\.Count\) selected template\(s\) now\?" -DefaultYes' -Because "the create/publish confirm (now for just the picked selection - 2026-09-15 pick-list rework) still defaults to Yes"

# functional: once CA_OcspResponderHost is set (by whichever menu asks first), a second visit to
# either place must not re-prompt - proves the two menus really do share one persisted answer
$sharedAns = [pscustomobject]@{ CA_OcspResponderHost = 'DOMAIN\CA01$' }
$viaGate = Resolve-CAAutoEnrollGatePrincipal -Token 'OcspResponderHost' -Spec $null -CAAnswers $sharedAns
Assert-Equal -Actual $viaGate -Expected 'DOMAIN\CA01$' -Because "the gate resolves the SAME CA_OcspResponderHost value menu 4 would have remembered - no second prompt, no drift between the two"

# ---------------------------------------------------------------------------
# 3. CA-Manager.ps1 - centralized save, once per menu-item completion
# ---------------------------------------------------------------------------
$rawDash = Get-Content -Path $Dashboard -Raw
Assert-Match   -Actual $rawDash -Pattern "Save-CAAnswers -Path \`$answersFile -Answers \`$script:CAAnswers" -Because "a single centralized Save-CAAnswers call exists"
$saveCount = ([regex]::Matches($rawDash, [regex]::Escape("Save-CAAnswers -Path `$answersFile -Answers `$script:CAAnswers"))).Count
Assert-Equal -Actual $saveCount -Expected 1 -Because "it fires exactly ONCE, centrally, not per-case any more (the old per-case opt-in only covered 4 of the 16 numbered items)"
Assert-Match -Actual $rawDash -Pattern '(?s)switch -Regex \(\$choice\) \{.*\n\s+\}\r?\n\s+# Centralized save' -Because "the centralized save sits right after the switch closes, so it runs after EVERY dispatched case, not just some of them"

Write-TestSummary -Suite "CA-Manager Persistence Audit"
