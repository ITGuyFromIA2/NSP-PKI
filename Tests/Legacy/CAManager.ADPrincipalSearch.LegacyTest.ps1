# Ported from NSP-FGTIPSecTools Tests\CAManager.ADPrincipalSearch.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for CA Manager's interactive AD group/computer search (2026-09-11), per the maintainer: the OCSP
    responder host / group prompt (menu 4) used to take a typed name verbatim, only discovering a
    typo/wrong-suffix mismatch later when the ACL grant itself failed with an opaque "could not
    resolve to a security identifier" error. Now runs through Resolve-CAADPrincipalInteractive
    (CACore.ps1) - same 0/1/many-hit search UX already proven twice in this codebase (the umbrella
    nested-group picker inline in CATemplates.ps1; NPS-Manager's Resolve-NPSGroupInteractive) - via a
    new -Resolve scriptblock param on Get-CAAnswerOrPromptOptional (CAInteractive.ps1).

    Repo convention (Tests\README.md) - NOT Pester. Get-ADGroup/Get-ADComputer are mocked (this repo
    has no live AD to test against) by defining same-named functions after dot-sourcing CACore.ps1 -
    "later definition wins".
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$PKIModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$PKIModuleRoot\Private"

Test-ScriptParses -Path "$Mod\CACore.ps1"        -Because "CACore.ps1 parses after Resolve-CAADPrincipalInteractive"
Test-ScriptParses -Path "$Mod\CAInteractive.ps1" -Because "CAInteractive.ps1 parses after Get-CAAnswerOrPromptOptional's -Resolve param + the menu 4 wiring"
Test-ScriptParses -Path "$Mod\CATemplates.ps1"   -Because "CATemplates.ps1 parses after Resolve-CAUmbrellaGroup's AD-Manager cross-link"

. "$Mod\CACore.ps1"
. "$Mod\CAInteractive.ps1"
. "$Mod\CATemplates.ps1"

$env:USERDOMAIN = 'CONTOSO'

# ---------------------------------------------------------------------------
# 1. No AD module available - saves the typed term as-is, unresolved, no crash
# ---------------------------------------------------------------------------
if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue)    { Remove-Item function:Get-ADGroup }
if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) { Remove-Item function:Get-ADComputer }
$noAD = Resolve-CAADPrincipalInteractive -SearchTerm 'SomeGroup'
Assert-Equal -Actual $noAD -Expected 'SomeGroup' -Because "with no AD module available, the typed term is saved as-is rather than throwing"

# ---------------------------------------------------------------------------
# Mocks for the rest - a small fake AD with groups + computers
# ---------------------------------------------------------------------------
$script:__fakeGroups    = @(
    [pscustomobject]@{ Name = 'OCSP-Responders' }
    [pscustomobject]@{ Name = 'OCSP-Backup-Responders' }
)
$script:__fakeComputers = @(
    [pscustomobject]@{ Name = 'CONTOSO-CA'; SamAccountName = 'CONTOSO-CA$' }
    [pscustomobject]@{ Name = 'CONTOSO-CA2'; SamAccountName = 'CONTOSO-CA2$' }
)
function Get-ADGroup {
    param([string]$Filter, [string]$ErrorAction)
    if ($Filter -match "Name -eq '([^']+)'")   { return @($script:__fakeGroups | Where-Object { $_.Name -eq $Matches[1] }) }
    if ($Filter -match "Name -like '\*([^*]*)\*'") { return @($script:__fakeGroups | Where-Object { $_.Name -like "*$($Matches[1])*" }) }
    return @()
}
function Get-ADComputer {
    param([string]$Filter, [string]$ErrorAction)
    if ($Filter -match "Name -eq '([^']+)'")   { return @($script:__fakeComputers | Where-Object { $_.Name -eq $Matches[1] }) }
    if ($Filter -match "Name -like '\*([^*]*)\*'") { return @($script:__fakeComputers | Where-Object { $_.Name -like "*$($Matches[1])*" }) }
    return @()
}

# ---------------------------------------------------------------------------
# 2. Exact match - group
# ---------------------------------------------------------------------------
$exactGroupResult = Resolve-CAADPrincipalInteractive -SearchTerm 'OCSP-Responders'
Assert-Equal -Actual $exactGroupResult -Expected 'CONTOSO\OCSP-Responders' -Because "an exact, unambiguous group name resolves directly, no prompt needed"

# ---------------------------------------------------------------------------
# 3. Exact match - computer, typed WITH the trailing $ and a DOMAIN\ prefix (the prompt's own example
#    shape) - both are stripped before searching
# ---------------------------------------------------------------------------
$exactComputerResult = Resolve-CAADPrincipalInteractive -SearchTerm 'CONTOSO\CONTOSO-CA$'
Assert-Equal -Actual $exactComputerResult -Expected 'CONTOSO\CONTOSO-CA$' -Because "a computer's SamAccountName already carries the trailing `$ - the resolved value matches exactly what NTAccount(...).Translate(...) expects for a machine principal"

# ---------------------------------------------------------------------------
# 4. Wildcard search - exactly one combined hit across both object types
# ---------------------------------------------------------------------------
$oneHit = Resolve-CAADPrincipalInteractive -SearchTerm 'CA2'
Assert-Equal -Actual $oneHit -Expected 'CONTOSO\CONTOSO-CA2$' -Because "a wildcard search matching exactly one computer (and no groups) auto-resolves without a prompt"

# ---------------------------------------------------------------------------
# 5. Wildcard search - multiple hits, numbered pick-list, mocked Read-Host
# ---------------------------------------------------------------------------
$script:__rhQ = [System.Collections.Generic.Queue[string]]::new()
function Read-Host { param([string]$Prompt) if ($script:__rhQ.Count -eq 0) { throw "queue empty" } $script:__rhQ.Dequeue() }

$script:__rhQ.Enqueue('1')
$multiPick = Resolve-CAADPrincipalInteractive -SearchTerm 'OCSP'
Assert-Equal -Actual $multiPick -Expected 'CONTOSO\OCSP-Backup-Responders' -Because "'OCSP' matches 2 groups; sorted by Kind,Display puts Backup-Responders first alphabetically - picking '1' resolves to it"

$script:__rhQ.Enqueue('')
$multiSkip = Resolve-CAADPrincipalInteractive -SearchTerm 'OCSP'
Assert-Equal -Actual $multiSkip -Expected 'OCSP' -Because "a blank selection on a multi-hit pick-list keeps the ORIGINAL typed term, unresolved - never guesses"

# ---------------------------------------------------------------------------
# 6. Wildcard search - zero hits keeps the typed term, unresolved (no create-offer - unlike the
#    umbrella-group / NPS-group pickers, an OCSP responder host is virtually always pre-existing)
# ---------------------------------------------------------------------------
$zeroHits = Resolve-CAADPrincipalInteractive -SearchTerm 'NoSuchThingAtAll'
Assert-Equal -Actual $zeroHits -Expected 'NoSuchThingAtAll' -Because "zero hits keeps the typed term as-is, unresolved"
$srcResolve = (Get-Command Resolve-CAADPrincipalInteractive).Definition
Assert-NoMatch -Actual $srcResolve -Pattern 'New-ADGroup|New-ADComputer' -Because "never offers to CREATE anything - this field names an existing principal, not one to provision"

# ---------------------------------------------------------------------------
# 7. Get-CAAnswerOrPromptOptional's new -Resolve param
# ---------------------------------------------------------------------------
function Read-Host { param([string]$Prompt) if ($script:__rhQ.Count -eq 0) { throw "queue empty" } $script:__rhQ.Dequeue() }   # restore queue mock (Resolve-CAADPrincipalInteractive's own tests redefined it above)

$ansResolve = [pscustomobject]@{}
$script:__rhQ.Enqueue('OCSP-Responders')   # the typed search term at the prompt itself
$resolved = Get-CAAnswerOrPromptOptional -CAAnswers $ansResolve -Field 'CA_OcspResponderHost' -Prompt 'x' -Resolve { param($term) Resolve-CAADPrincipalInteractive -SearchTerm $term }
Assert-Equal -Actual $resolved -Expected 'CONTOSO\OCSP-Responders' -Because "the RESOLVED value (not the raw typed term) is what's returned"
Assert-Equal -Actual $ansResolve.CA_OcspResponderHost -Expected 'CONTOSO\OCSP-Responders' -Because "...and what gets remembered onto `$CAAnswers"

# blank stays blank - -Resolve is never invoked on a skip
$ansBlank = [pscustomobject]@{}
$resolveCalls = 0
$script:__rhQ.Enqueue('')
$blankResult = Get-CAAnswerOrPromptOptional -CAAnswers $ansBlank -Field 'CA_OcspResponderHost' -Prompt 'x' -Resolve { param($term) $script:resolveCalls++; $term }
Assert-True  -Condition ([string]::IsNullOrWhiteSpace($blankResult)) -Because "a blank/skip answer is returned as-is"
Assert-Equal -Actual $resolveCalls -Expected 0 -Because "-Resolve is never invoked on a blank answer - skip stays skip"
Assert-False -Condition ([bool]$ansBlank.PSObject.Properties['CA_OcspResponderHost']) -Because "and nothing gets remembered either, same as before -Resolve existed"

# an already-answered field short-circuits BEFORE any prompt/resolve - never re-searched on a later visit
$ansAlready = [pscustomobject]@{ CA_OcspResponderHost = 'CONTOSO\AlreadyResolved$' }
$resolveCalls2 = 0
$already = Get-CAAnswerOrPromptOptional -CAAnswers $ansAlready -Field 'CA_OcspResponderHost' -Prompt 'x' -Resolve { param($term) $script:resolveCalls2++; $term }
Assert-Equal -Actual $already -Expected 'CONTOSO\AlreadyResolved$' -Because "an already-saved value returns immediately"
Assert-Equal -Actual $resolveCalls2 -Expected 0 -Because "-Resolve never runs on the already-answered fast path - an already-resolved value is never re-searched"

# ---------------------------------------------------------------------------
# 8. Menu 4 wiring - BOTH the OCSP-responder-host AND the umbrella-group prompts
# ---------------------------------------------------------------------------
$srcMenu4 = (Get-Command Invoke-CAMenuTemplates).Definition
$resolveWireCount = ([regex]::Matches($srcMenu4, "-Resolve \{ param\(\`$term\) Resolve-CAADPrincipalInteractive -SearchTerm \`$term \}")).Count
Assert-Equal -Actual $resolveWireCount -Expected 2 -Because "menu 4 wires the interactive AD search to BOTH the OCSP-responder-host AND the umbrella-group prompts (2026-09-11 - built for OCSP-host first, reused for umbrella since it's the same 'resolve a name to a real AD principal' shape)"
Assert-Match -Actual $srcMenu4 -Pattern "Field 'CA_AutoEnrollGroup'[\s\S]{0,200}?-Resolve \{ param\(\`$term\) Resolve-CAADPrincipalInteractive -SearchTerm \`$term \}" -Because "specifically the umbrella-group (CA_AutoEnrollGroup) prompt is wired, not just the OCSP one twice over"

# ---------------------------------------------------------------------------
# 9. Resolve-CAUmbrellaGroup - 2026-09-14: stale "dashboard option M" fixed (RSAT install has been
#    numbered menu 1 since the 2026-09-10 renumber, never an "M" letter-key), and a new AD-Manager
#    cross-link added at the exact "no group exists yet" decision point (the maintainer: cross-link AD-Manager
#    from the appropriate places in the RADIUS/CA managers)
# ---------------------------------------------------------------------------
$srcUmbrella = (Get-Command Resolve-CAUmbrellaGroup).Definition
Assert-NoMatch -Actual $srcUmbrella -Pattern 'dashboard option M' -Because "stale pre-numbered-menu text - RSAT install has been menu 1 since the 2026-09-10 renumber, never a letter-key 'M'"
Assert-Match   -Actual $srcUmbrella -Pattern 'dashboard menu 1' -Because "the no-AD-module message now names the correct current menu item"
Assert-Match   -Actual $srcUmbrella -Pattern 'AD-Manager tool instead \(menu 2 there\)' -Because "the 'no group exists yet' path points at AD-Manager's own fuller, OU-browsable scaffold tool before offering its own quick single-group create"
Assert-Match   -Actual $srcUmbrella -Pattern 'See also: PushableTools\\ADManager' -Because "the function's own doc-comment also cross-references AD-Manager, for a future reader of the code, not just the interactive prompt"

Write-TestSummary -Suite "CA-Manager AD Principal Search (OCSP responder host + umbrella group)"
