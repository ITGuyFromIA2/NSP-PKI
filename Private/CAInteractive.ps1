<#
.SYNOPSIS
    Shared Read-Host-driven wizard helpers for CA Manager. Requires Modules\CACore.ps1 to already be
    dot-sourced (Write-CAHeader etc.).

.DESCRIPTION
    Phase 1 content is intentionally minimal - just the small prompt helpers the later-phase
    wizards (template creation, umbrella-group nesting, GPO push, App Proxy, test-cert suite) will
    all share. The wizards themselves land in their own phases.
#>

# ---------------------------------------------------------------------------
function Read-CAConfirm {
    <#
    .SYNOPSIS
        Y/N confirmation prompt. Returns [bool]. Blank input -> $DefaultYes.
    #>
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [switch]$DefaultYes
    )
    $suffix = if ($DefaultYes) { ' [Y/n]' } else { ' [y/N]' }
    while ($true) {
        $r = Read-Host ($Prompt + $suffix)
        if ([string]::IsNullOrWhiteSpace($r)) { return [bool]$DefaultYes }
        if ($r -match '^(?i)y(es)?$') { return $true }
        if ($r -match '^(?i)n(o)?$')  { return $false }
        Write-Host "  Please answer y or n." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Back-navigation (2026-09-10, Part A item 3) - reuses CLIBuilder's own convention (a literal 'B'
# input steps back one prompt) rather than inventing a second idiom. $script:CABackSignal is a
# private sentinel string, astronomically unlikely to collide with real user input (a path, a name,
# a hostname); Test-CABackSignal is the one place that comparison lives, so call sites never need to
# know the sentinel's literal value. Only offered where a wizard is a genuinely undo-able SEQUENCE OF
# PROMPTS with no mutating action interleaved between them - see the .NOTES on each rollout site for
# why a given wizard does or doesn't offer it end-to-end.
$script:CABackSignal = '<<CA_BACK>>'

function Test-CABackSignal {
    <#
    .SYNOPSIS
        True if $Value is the "go back one prompt" sentinel a back-aware prompt helper returned.
    #>
    param($Value)
    return ($Value -is [string]) -and ($Value -ceq $script:CABackSignal)
}

# ---------------------------------------------------------------------------
function Read-CANonEmpty {
    <#
    .SYNOPSIS
        Prompts until a non-blank value is entered (or, if -CurrentValue is given, blank keeps it).
    .PARAMETER AllowBack
        When set, a literal 'B'/'Back' response returns $script:CABackSignal (see Test-CABackSignal)
        instead of being treated as the value - pass this only when the caller is actually prepared
        to step back to a previous prompt (there IS one), same as CLIBuilder's $CanGoBack convention.
    #>
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$CurrentValue,
        [switch]$AllowBack
    )
    $hint = if ($PSBoundParameters.ContainsKey('CurrentValue') -and -not [string]::IsNullOrWhiteSpace($CurrentValue)) {
        " (blank to keep '$CurrentValue')"
    } else { '' }
    $backHint = if ($AllowBack) { '  [B = back]' } else { '' }
    while ($true) {
        $r = Read-Host ($Prompt + $hint + $backHint)
        if ($AllowBack -and $r -match '^(?i)b(ack)?$') { return $script:CABackSignal }
        if ([string]::IsNullOrWhiteSpace($r)) {
            if (-not [string]::IsNullOrWhiteSpace($CurrentValue)) { return $CurrentValue }
            Write-Host "  A value is required." -ForegroundColor Yellow
            continue
        }
        return $r.Trim()
    }
}

# ---------------------------------------------------------------------------
function Read-CAOptional {
    <#
    .SYNOPSIS
        A single Read-Host for a field that's allowed to be blank (no "value is required" loop) -
        the back-aware equivalent of a bare Read-Host call, for wizard prompts that accept an empty
        answer (skip / default) rather than requiring one.
    #>
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [switch]$AllowBack
    )
    $backHint = if ($AllowBack) { '  [B = back]' } else { '' }
    $r = Read-Host ($Prompt + $backHint)
    if ($AllowBack -and $r -match '^(?i)b(ack)?$') { return $script:CABackSignal }
    return $r
}

# ---------------------------------------------------------------------------
function Invoke-CAWizardSteps {
    <#
    .SYNOPSIS
        Drives an ordered array of prompt steps with back-navigation, mirroring CLIBuilder's
        $EntryIdx loop (Interactive - IPSec_IKEV2- CLI Builder V2.ps1): each step is a scriptblock
        taking one [bool]$CanGoBack argument (true once there's a prior step to return to) and
        returning either a value or $script:CABackSignal (via a back-aware prompt helper above).
        Stepping back always re-runs the step you land on from scratch - same "recompute fresh"
        convention CLIBuilder itself uses, not a rewind to a remembered prior answer.
    .PARAMETER Steps
        Array of @{ Name = '...'; Run = { param($CanGoBack) ... } } entries, in order.
    .OUTPUTS
        A hashtable keyed by each step's Name, holding what its Run scriptblock returned (skipping
        back-signal iterations - only the FINAL, accepted value per step lands in the result).
    #>
    param([Parameter(Mandatory)][object[]]$Steps)
    $result = @{}
    $i = 0
    while ($i -lt $Steps.Count) {
        $step = $Steps[$i]
        $r = & $step.Run ($i -gt 0)
        # Clamp rather than decrement past 0 - a bare "$i--" here would take $i to -1, and PowerShell
        # arrays support negative indexing, so $Steps[-1] would silently jump to the LAST step instead
        # of refusing to go back further. A step should never return the back signal when its own
        # $CanGoBack was false, but this is the defense-in-depth net if one does anyway.
        if (Test-CABackSignal $r) { $i = [Math]::Max(0, $i - 1); continue }
        $result[$step.Name] = $r
        $i++
    }
    return $result
}

# ---------------------------------------------------------------------------
function Test-SecureStringMatch {
    <#
    .SYNOPSIS
        Returns $true if two SecureStrings hold the same plaintext. Used to confirm a
        "type it twice" password prompt without ever printing the value.
    #>
    param(
        [Parameter(Mandatory)][securestring]$A,
        [Parameter(Mandatory)][securestring]$B
    )
    $pa = [System.Net.NetworkCredential]::new('x', $A).Password
    $pb = [System.Net.NetworkCredential]::new('x', $B).Password
    return ($pa -ceq $pb) -and -not [string]::IsNullOrEmpty($pa)
}

# ---------------------------------------------------------------------------
function Get-CAAnswerOrPrompt {
    <#
    .SYNOPSIS
        Returns $CAAnswers.<Field> if set, otherwise prompts for it (and, if -Remember, writes it
        back onto the in-memory $CAAnswers object so later steps in the same session reuse it).
    .PARAMETER Default
        Optional. When given, blank Enter at the prompt accepts this value instead of re-prompting -
        pass it whenever -Prompt itself displays a bracketed default (e.g. "... [C:\PolicyFiles]"), or
        blank Enter will loop with "A value is required." even though the prompt implied one exists
        (found live 2026-09-10, menu S's policy-directory prompt).
    .PARAMETER AllowBack
        Only meaningful when this call actually prompts (a remembered/already-set $cur short-circuits
        before any prompt happens, so there's nothing to back out of). Pass the caller's own
        "is there a previous step" condition - typically an Invoke-CAWizardSteps step's $CanGoBack
        argument. When the operator types B/Back, returns $script:CABackSignal (Test-CABackSignal)
        instead of prompting further or writing anything back - the caller decides what "back" means.
    #>
    param(
        [Parameter(Mandatory)]$CAAnswers,
        [Parameter(Mandatory)][string]$Field,
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default,
        [switch]$Remember,
        [switch]$AllowBack
    )
    $cur = if ($CAAnswers -and $CAAnswers.PSObject.Properties[$Field]) { $CAAnswers.$Field } else { $null }
    if (-not [string]::IsNullOrWhiteSpace($cur)) { return $cur }
    $val = if ($PSBoundParameters.ContainsKey('Default')) { Read-CANonEmpty -Prompt $Prompt -CurrentValue $Default -AllowBack:$AllowBack } else { Read-CANonEmpty -Prompt $Prompt -AllowBack:$AllowBack }
    if (Test-CABackSignal $val) { return $val }
    if ($Remember -and $CAAnswers) {
        if ($CAAnswers.PSObject.Properties[$Field]) { $CAAnswers.$Field = $val }
        else { $CAAnswers | Add-Member -NotePropertyName $Field -NotePropertyValue $val -Force }
    }
    return $val
}

# ---------------------------------------------------------------------------
function Get-CAAnswerOrPromptOptional {
    <#
    .SYNOPSIS
        Like Get-CAAnswerOrPrompt, but for a field where BLANK is a legitimate answer (e.g. "skip
        this ACL for now") - never forces a non-empty retry loop. A non-blank answer is always
        remembered onto $CAAnswers (persistence-audit fix, 2026-09-10: several such fields used to be
        bare, unremembered Read-Host calls, re-asked every run even after a real answer was already
        given). A BLANK answer is deliberately NOT remembered - it keeps asking again next time,
        preserving the "skip for now" promise these prompts make rather than silently locking in
        "never configure this" forever the first time someone leaves it blank.
    .PARAMETER Resolve
        2026-09-11, per the maintainer: optional scriptblock, given the raw typed (non-blank) value, returning
        the FINAL value to actually store - e.g. Resolve-CAADPrincipalInteractive turning a typed
        search term into a real, disambiguated "DOMAIN\Name". Only runs on a NON-blank typed answer
        (blank/skip never invokes it - "skip for now" stays exactly that). Only runs on a FRESH prompt,
        never on the already-answered fast path above - an already-resolved, already-saved value is
        never re-searched on a later visit to the same menu.
    #>
    param(
        [Parameter(Mandatory)]$CAAnswers,
        [Parameter(Mandatory)][string]$Field,
        [Parameter(Mandatory)][string]$Prompt,
        [switch]$AllowBack,
        [scriptblock]$Resolve
    )
    $cur = if ($CAAnswers -and $CAAnswers.PSObject.Properties[$Field]) { $CAAnswers.$Field } else { $null }
    if (-not [string]::IsNullOrWhiteSpace($cur)) { return $cur }
    $val = Read-CAOptional -Prompt $Prompt -AllowBack:$AllowBack
    if (Test-CABackSignal $val) { return $val }
    if (-not [string]::IsNullOrWhiteSpace($val) -and $Resolve) {
        $val = & $Resolve $val
    }
    if (-not [string]::IsNullOrWhiteSpace($val) -and $CAAnswers) {
        if ($CAAnswers.PSObject.Properties[$Field]) { $CAAnswers.$Field = $val }
        else { $CAAnswers | Add-Member -NotePropertyName $Field -NotePropertyValue $val -Force }
    }
    return $val
}

# --- dashboard menu-action wrappers (each gathers the CA_* values it needs, then calls the engine
#     in Modules\CA*.ps1; everything mutating goes through Invoke-CAStep so dry-run is honoured) ---

function Invoke-CAMenuPrereqs {
    <#
    .PARAMETER ScriptPath / ShimPath / CAConfigName
        2026-09-11: passed through only so this menu can offer an immediate "relaunch CA-Manager"
        once it's actually installed something - see Invoke-CAManagerRelaunch (CACore.ps1). Optional;
        blank just means the relaunch offer is skipped (falls back to the old "re-launch by hand"
        message), never a hard failure.
    #>
    param(
        [string]$ScriptPath,
        [string]$ShimPath,
        [string]$CAConfigName
    )
    Write-CAHeader "Install RSAT / management modules"
    $st = Get-CAManagementPrereqStatus
    Write-Host ("  ActiveDirectory module        : {0}" -f $(if ($st.ActiveDirectory) { 'present' } else { 'MISSING - needed for menu 5 (umbrella group)' })) -ForegroundColor $(if ($st.ActiveDirectory) { 'Green' } else { 'Yellow' })
    Write-Host ("  GroupPolicy module            : {0}" -f $(if ($st.GroupPolicy)     { 'present' } else { 'MISSING - needed for menu 14 (inventory GPO report)' })) -ForegroundColor $(if ($st.GroupPolicy) { 'Green' } else { 'Yellow' })
    Write-Host ("  Microsoft.Graph.Authentication : {0}" -f $(if ($st.GraphAuth)      { 'present' } else { 'MISSING - needed for menu 6 (App Proxy)' })) -ForegroundColor $(if ($st.GraphAuth) { 'Green' } else { 'Yellow' })
    Write-Host ""
    # 2026-09-11, per the maintainer's Y/N-defaults review: every prompt below now defaults to Yes - said
    # explicitly here so a tech blank-Entering through them knows that's what's about to happen,
    # rather than assuming Enter means "skip".
    Write-Host "  Everything below defaults to Yes - answer N for anything you don't want on this box." -ForegroundColor Cyan
    Write-Host ""
    $adcs = Read-CAConfirm -Prompt "Also install the AD CS management tools (certtmpl / pkiview)?" -DefaultYes
    $ocsp = Read-CAConfirm -Prompt "Also install the Online Responder management tools?" -DefaultYes
    $didInstall = $false
    # Gather every "what to install" choice BEFORE the one "Proceed?" that actually triggers
    # everything (2026-09-11, per the maintainer - Graph Auth used to be asked AFTER the RSAT install had
    # already run, so a tech had to answer a second, separate "proceed" mid-flow instead of reviewing
    # and confirming the whole plan in one go).
    $installGraph = -not $st.GraphAuth -and (Read-CAConfirm -Prompt "Install Microsoft.Graph.Authentication (machine-wide) now?" -DefaultYes)
    if (Read-CAConfirm -Prompt "`nProceed?" -DefaultYes) {
        Install-CAManagementPrereqs -IncludeAdcsTools:$adcs -IncludeOcspTools:$ocsp
        $didInstall = $true
    }
    if ($installGraph) {
        try { Install-CAGraphModule; $didInstall = $true }
        catch { Write-Host "  $($_.Exception.Message)" -ForegroundColor Red }
    }
    # Offer to relaunch right here instead of just telling the tech to do it by hand - only makes
    # sense if we actually attempted a real (non-dry-run) install, and only if the caller gave us
    # enough to relaunch with (ScriptPath). Also reachable any time from the dashboard's own 'R' key.
    if ($didInstall -and -not (Get-CADryRun) -and -not [string]::IsNullOrWhiteSpace($ScriptPath) `
        -and (Get-Command Invoke-CAManagerRelaunch -ErrorAction SilentlyContinue) `
        -and (Read-CAConfirm -Prompt "`nRelaunch CA-Manager now so the new modules load?" -DefaultYes)) {
        Invoke-CAManagerRelaunch -ScriptPath $ScriptPath -ShimPath $ShimPath -CAConfigName $CAConfigName
        return   # unreached in practice - Invoke-CAManagerRelaunch exits the process - but keeps this function's own flow honest
    }
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}

function Invoke-CAMenuInstall {
    param($CAAnswers)
    Write-CAHeader "Install / configure the CA"
    if ($CAAnswers -and ($CAAnswers.CA_IsSubordinate -match '^(?i)y')) {
        Write-Host "This client is flagged CA_IsSubordinate = Yes. The subordinate install path" -ForegroundColor Yellow
        Write-Host "(CSR -> submit to the online root -> install chain) is not built yet - do it by hand," -ForegroundColor Yellow
        Write-Host "then use the other menu items for templates / OCSP / GPO / App Proxy." -ForegroundColor Yellow
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    # The menu-1 step, up front: menu 2 needs the AD + ADCS management modules (RSAT-AD-PowerShell / GPMC /
    # RSAT-ADCS-Mgmt). Idempotent + dry-run aware; a fresh install here still needs a relaunch (and
    # usually a reboot) before the modules import - Invoke-CAInstall's guard catches that.
    if (Get-Command Install-CAManagementPrereqs -ErrorAction SilentlyContinue) {
        Write-Host "  Checking management prerequisites (RSAT AD / GroupPolicy / ADCS tools)..." -ForegroundColor DarkGray
        Install-CAManagementPrereqs -IncludeAdcsTools
        Write-Host ""
    }

    $cn  = Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_CommonName'    -Prompt "Issuing CA common name" -Remember
    $yrs = [int](Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_ValidityYears' -Prompt "CA cert lifetime (years)" -Remember)
    if ($yrs -lt 10) {
        Write-Host ""
        Write-Host "  CA cert lifetime is set to $yrs year(s). A single-tier CA is its own root -" -ForegroundColor Yellow
        Write-Host "  renewing it means re-establishing trust everywhere; 10-15 is the norm." -ForegroundColor Yellow
        $ans = Read-Host "  New value in years, or Enter to keep $yrs"
        if ($ans -as [int]) {
            $yrs = [int]$ans
            if ($CAAnswers) { $CAAnswers | Add-Member -NotePropertyName CA_ValidityYears -NotePropertyValue "$yrs" -Force }
        }
    }
    Show-CAInstallPlan -CAAnswers $CAAnswers
    if (Read-CAConfirm -Prompt "`nProceed?" ) {
        Invoke-CAInstall -CACommonName $cn -ValidityYears $yrs `
            -CrlPeriodDays $([int](Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_CrlPeriodDays' -Prompt "CRL period (days)" -Remember))
    }
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}

function Invoke-CAMenuTemplates {
    param($CAAnswers)
    Write-CAHeader "Create / update certificate templates"

    $spec = Get-CATemplateSpecForAnswers -CAAnswers $CAAnswers

    # Persistence-audit fix (2026-09-10): both used to be bare Read-Host calls, re-asked on every
    # visit to this menu even after a real answer was already typed once. CA_OcspResponderHost is
    # also the exact field the enrollment gate (menu 15, Resolve-CAAutoEnrollGatePrincipal) reads for
    # the SAME principal - sharing the field means the tech is never asked for this host twice across
    # two different menus, and the gate always resolves to whoever actually got granted Enroll here.
    # 2026-09-11, per the maintainer: neither is taken verbatim any more - a typed name/wildcard now runs
    # through an interactive AD group/computer search-and-pick (Resolve-CAADPrincipalInteractive,
    # CACore.ps1) before being saved, same 0/1/many-hit UX already proven elsewhere in this codebase
    # (the umbrella nested-group picker just below, NPS-Manager's Resolve-NPSGroupInteractive) -
    # catches a typo/wrong-suffix mismatch here instead of at the ACL grant, where it used to fail
    # with an opaque "could not resolve to a security identifier" error. Built for the OCSP-host field
    # first (an explicit ask); reused here for the umbrella group too - same field shape (a name that
    # has to resolve to a real AD principal), no reason for one to get the search and not the other.
    #
    # 2026-09-15, per the maintainer: asked FIRST now, before the (numbered) plan even renders - it's a quick,
    # usually-already-answered question that read oddly buried after a wall of per-template detail.
    $ocspHost = Get-CAAnswerOrPromptOptional -CAAnswers $CAAnswers -Field 'CA_OcspResponderHost' `
        -Prompt "OCSP responder host / group name (or partial - wildcard-searched) for the OCSPResponseSigning template ACL (e.g. $($env:COMPUTERNAME)) - blank to skip" `
        -Resolve { param($term) Resolve-CAADPrincipalInteractive -SearchTerm $term }

    # 2026-09-11, per the maintainer ("do we really need IKEv2_MasterGroup at this point? TameMyCerts... it's
    # just muddying the waters"): confirmed by reading the template-spec code - EnrollPrincipals only
    # ever contains 'Umbrella' on the single SHARED Auto template spec (Get-CAVpnTemplateSpec), which
    # Get-CATemplateSpecForAnswers drops entirely in favor of per-group 'GroupSpecific' templates the
    # moment TameMyCerts + RadiusGroupPairs are both in play - the now-recommended path. So the umbrella
    # group genuinely grants nothing in that mode. Rather than removing the field/prompt outright (a
    # non-TameMyCerts client, or a TameMyCerts one with no RadiusGroupPairs yet, still needs it - see
    # CATameMyCerts.ps1's own single-policy fallback), skip ASKING for it whenever nothing $spec is
    # about to create would actually use it - computed generically from $spec itself, not a hardcoded
    # CA_SubjectStampMode check, so this stays correct if the per-group-vs-shared logic changes later.
    $umbrellaNeeded = [bool]($spec | Where-Object { $_.EnrollPrincipals -contains 'Umbrella' -or $_.AutoEnrollPrincipals -contains 'Umbrella' })
    $umbrella = if ($umbrellaNeeded) {
        Get-CAAnswerOrPromptOptional -CAAnswers $CAAnswers -Field 'CA_AutoEnrollGroup' `
            -Prompt "`nAuto-enrollment umbrella group name (or partial - wildcard-searched) - blank to skip its ACLs for now" `
            -Resolve { param($term) Resolve-CAADPrincipalInteractive -SearchTerm $term }
    } else {
        if ($CAAnswers -and $CAAnswers.PSObject.Properties['CA_AutoEnrollGroup'] -and $CAAnswers.CA_AutoEnrollGroup) {
            Write-Host "`n  (skipping the umbrella-group prompt - none of the templates about to be created/updated use it; TameMyCerts's per-group templates grant Enroll directly to each pair's own AD group instead.)" -ForegroundColor DarkGray
        }
        $null
    }

    # 2026-09-15, per the maintainer: menu 4 used to show the plan then confirm ALL-OR-NOTHING
    # ("create/publish the N template(s) now?"). A TameMyCerts client with many RadiusGroupPairs
    # (one real client hit 11 templates once RadiusGroupPairs actually made it through staging - see that same
    # day's staging fix) usually only needs to (re)create ONE or two new/changed entries on a given
    # visit, not batch-touch every template every time - so the tech picks specific numbers instead
    # of an unconditional "all of them" (re-selecting an already-complete template is still harmless,
    # New-CAVpnTemplate skips it - this is purely better UX, not a new safety gate).
    #
    # 2026-09-15, same-day follow-up: the numbered FULL detail plan (every field/flag per template) was
    # too much to scan through just to pick numbers - terse by default now (just "[N] DisplayName"),
    # with 'D' to show the same full Show-CATemplatePlan detail on demand, then re-prompt.
    Write-Host ""
    Write-Host "  Templates to create/update:" -ForegroundColor Cyan
    for ($__pi = 0; $__pi -lt $spec.Count; $__pi++) { Write-Host ("    [{0}] {1}" -f ($__pi + 1), $spec[$__pi].DisplayName) -ForegroundColor Gray }

    $pickRaw = $null
    while ($true) {
        Write-Host ""
        Write-Host "  Which template number(s) to create/update now?" -ForegroundColor Cyan
        Write-Host "    Comma-separated numbers, 'A' for all $($spec.Count), 'D' for full detail, or blank to cancel." -ForegroundColor Gray
        $pickRaw = Read-Host "  Select"
        if ($pickRaw.Trim() -notmatch '^(?i)d(etail)?$') { break }
        Write-Host ""
        Show-CATemplatePlan -CAAnswers $CAAnswers -Numbered
    }

    if ([string]::IsNullOrWhiteSpace($pickRaw)) {
        Write-Host "  Nothing selected - cancelled." -ForegroundColor Gray
        Read-Host "`nPress Enter to return to the menu" | Out-Null
        return
    }

    $selectedSpec = @(if ($pickRaw.Trim() -match '^(?i)a(ll)?$') {
        $spec
    } else {
        $pickRaw -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ - 1 } | Where-Object { $_ -ge 0 -and $_ -lt $spec.Count } | ForEach-Object { $spec[$_] }
    })

    if (-not $selectedSpec.Count) {
        Write-Host "  No valid selection - cancelled." -ForegroundColor Yellow
        Read-Host "`nPress Enter to return to the menu" | Out-Null
        return
    }

    # 2026-09-15, per the maintainer: "for any 'template' we generate, we also need to allow a manual admin
    # request against it" - a per-group Auto template only ever grants Enroll/AutoEnroll to its own
    # pair's group; there was no way to manually request/troubleshoot that SAME group's cert shape
    # without falling back to the one generic shared Manual template. Opt-in (defaults No - this is
    # additive, not every group needs its own manual counterpart every time).
    $groupSpecsInSelection = @($selectedSpec | Where-Object { "$($_.Key)" -like 'Group_*' })
    if ($groupSpecsInSelection.Count -and (Read-CAConfirm -Prompt "`nAlso add manual (admin-approved, exportable) version(s) for the $($groupSpecsInSelection.Count) selected group template(s)?")) {
        $manualAdds = @($groupSpecsInSelection | ForEach-Object { Get-CAPerGroupManualTemplateSpec -GroupSpec $_ })
        $selectedSpec = @($selectedSpec) + $manualAdds
    }

    Write-Host ""
    Write-Host "  Selected:" -ForegroundColor Cyan
    foreach ($s in $selectedSpec) { Write-Host "    - $($s.DisplayName)" -ForegroundColor Gray }

    # 2026-09-11, per the maintainer's Y/N-defaults review ("what harm is it changing this to default Y? We
    # re-imported many times over the top when testing") - confirmed safe: New-CAVpnTemplate already
    # checks [ADSI]::Exists first and just skips (no error, no duplicate, no destructive rewrite) when
    # a complete template with this CN is already there - genuinely idempotent, matches the maintainer's own
    # live-tested experience re-running this menu repeatedly.
    if (-not (Read-CAConfirm -Prompt "`nCreate/publish the $($selectedSpec.Count) selected template(s) now?" -DefaultYes)) {
        Read-Host "`nPress Enter to return to the menu" | Out-Null
        return
    }

    $created = New-Object System.Collections.Generic.List[string]
    foreach ($t in $selectedSpec) {
        Write-Host ""
        Write-Host "  --- $($t.DisplayName) ---" -ForegroundColor Cyan
        try {
            $cn = New-CAVpnTemplate -Spec $t

            foreach ($p in $t.EnrollPrincipals) {
                $who = switch ($p) {
                    'Umbrella'                  { $umbrella }
                    'OcspResponderHost'         { $ocspHost }
                    'GroupSpecific'             { $t.GroupName }   # per-group Auto template (TameMyCerts model) - ACL to just this pair's AD group
                    'DomainAndEnterpriseAdmins' { $null }   # Domain/Enterprise Admins already have Enroll via inherited ACEs on a fresh template base
                    default                    { $p }
                }
                if ($who) {
                    # Enroll-only at creation, always - NEVER -AutoEnroll here anymore. "The
                    # enrollment gate" (Invoke-CAMenuAutoEnrollGate) is now the one place AutoEnroll
                    # gets turned on, deliberately, per group, decoupled from template creation order.
                    # $t.AutoEnrollPrincipals still names WHO should eventually get it - the gate menu
                    # reads that, this call site no longer acts on it directly.
                    Grant-CATemplateEnrollment -TemplateInternalName $cn -PrincipalName $who
                }
            }
            $created.Add($cn)
        } catch {
            Write-Host "  ERROR on $($t.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
            Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
            if (-not (Read-CAConfirm -Prompt "  Continue with the next template?" -DefaultYes)) { break }
        }
    }

    # Publish in ONE write - a per-template certutil -SetCATemplates loop loses all but the last
    # entry on a single DC (each call read-modify-writes certificateTemplates).
    if ($created.Count) {
        Write-Host ""
        try { Add-CAPublishedTemplate -TemplateName $created }
        catch {
            Write-Host "  ERROR publishing templates to the CA: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
        }
    }

    # Sweep OID husks left by any failed create attempts this run or earlier.
    Write-Host ""
    try { Remove-CAOrphanTemplateOids | Out-Null } catch { Write-Host "  (orphan-OID sweep skipped: $($_.Exception.Message))" -ForegroundColor DarkGray }

    Write-Host ""
    Write-Host "Done. Check with:  certutil -CATemplates" -ForegroundColor Green
    Read-Host "Press Enter to return to the menu" | Out-Null
}

function Invoke-CAMenuAdHocTemplate {
    <#
    .SYNOPSIS
        Menu 17 (Part A item 5, 2026-09-10). Creates ONE certificate template OUTSIDE the
        RadiusGroupPairs-driven flow menu 4 owns - for the one-off "just need a template for X" ask,
        without hijacking the per-group/Auto/Manual/FortiGate/OCSP batch. Reuses
        New-CAVpnTemplate / Grant-CATemplateEnrollment / Add-CAPublishedTemplate /
        Remove-CAOrphanTemplateOids completely unchanged - only the spec comes from the new
        Get-CAAdHocTemplateSpec (CATemplates.ps1) instead of Get-CATemplateSpecForAnswers. Grants
        Enroll only, same as menu 4 - AutoEnroll is still the enrollment gate's job alone (menu 15).
    #>
    param($CAAnswers)
    Write-CAHeader "Add a new template ad-hoc"

    $purposes = @(Get-CAAdHocTemplatePurposes)
    if (-not $purposes.Count) {
        Write-Host "  No ad-hoc template purposes configured (see Get-CAAdHocTemplatePurposes)." -ForegroundColor Red
        Read-Host "`nPress Enter to return to the menu" | Out-Null
        return
    }

    # A clean, undo-able SEQUENCE OF PROMPTS with no mutating action interleaved - same shape as menu
    # 14's back-nav rollout, and for the same reason it's safe here: nothing touches AD/the CA until
    # after every answer below is collected and the operator explicitly confirms the plan.
    $steps = @(
        @{ Name = 'DisplayName'; Run = { param($CanGoBack) Read-CANonEmpty -Prompt "Template display name" -AllowBack:$CanGoBack } }
        @{ Name = 'PurposeKey'; Run = {
            param($CanGoBack)
            if ($purposes.Count -eq 1) {
                Write-Host "  Purpose: $($purposes[0].Label)  (the only one configured today)" -ForegroundColor Gray
                return $purposes[0].Key
            }
            Write-Host ""
            for ($i = 0; $i -lt $purposes.Count; $i++) { Write-Host ("    {0}. {1}" -f ($i + 1), $purposes[$i].Label) }
            $pick = Read-CAOptional -Prompt "  Purpose number" -AllowBack:$CanGoBack
            if (Test-CABackSignal $pick) { return $pick }
            $idx = 0
            if (-not [int]::TryParse($pick, [ref]$idx) -or $idx -lt 1 -or $idx -gt $purposes.Count) {
                Write-Host "  Not a valid choice - defaulting to 1." -ForegroundColor Yellow
                $idx = 1
            }
            $purposes[$idx - 1].Key
        } }
        @{ Name = 'ValidityDays'; Run = {
            param($CanGoBack)
            $r = Read-CAOptional -Prompt "  Validity in days [365]" -AllowBack:$CanGoBack
            if (Test-CABackSignal $r) { return $r }
            $v = 0
            if ([string]::IsNullOrWhiteSpace($r) -or -not [int]::TryParse($r, [ref]$v) -or $v -le 0) { 365 } else { $v }
        } }
        @{ Name = 'OverlapDays'; Run = {
            param($CanGoBack)
            $r = Read-CAOptional -Prompt "  Renewal overlap in days [42]" -AllowBack:$CanGoBack
            if (Test-CABackSignal $r) { return $r }
            $v = 0
            if ([string]::IsNullOrWhiteSpace($r) -or -not [int]::TryParse($r, [ref]$v) -or $v -le 0) { 42 } else { $v }
        } }
        @{ Name = 'ExportableKey'; Run = {
            param($CanGoBack)
            $r = Read-CAOptional -Prompt "  Exportable private key? [y/N]" -AllowBack:$CanGoBack
            if (Test-CABackSignal $r) { return $r }
            [bool]($r -match '^(?i)y(es)?$')
        } }
        @{ Name = 'EnrollPrincipal'; Run = {
            param($CanGoBack)
            Read-CAOptional -Prompt "  Grant Enroll to (DOMAIN\name or group - blank to skip for now)" -AllowBack:$CanGoBack
        } }
    )
    $wiz = Invoke-CAWizardSteps -Steps $steps

    if ($wiz.OverlapDays -ge $wiz.ValidityDays) {
        Write-Host "  Overlap ($($wiz.OverlapDays)d) must be LESS than validity ($($wiz.ValidityDays)d) - adjusting overlap down." -ForegroundColor Yellow
        $wiz.OverlapDays = [Math]::Max(1, [Math]::Floor($wiz.ValidityDays / 2))
    }

    $spec = Get-CAAdHocTemplateSpec -DisplayName $wiz.DisplayName -PurposeKey $wiz.PurposeKey `
        -ValidityDays $wiz.ValidityDays -OverlapDays $wiz.OverlapDays -ExportableKey:$wiz.ExportableKey
    $purposeLabel = ($purposes | Where-Object { $_.Key -eq $wiz.PurposeKey }).Label

    Write-Host ""
    Write-Host "  --- Plan ---" -ForegroundColor Cyan
    Write-Host ("  DisplayName    : {0}" -f $spec.DisplayName)
    Write-Host ("  Purpose        : {0}" -f $purposeLabel)
    Write-Host ("  Validity       : {0}d (overlap {1}d)" -f $spec.ValidityDays, $spec.OverlapDays)
    Write-Host ("  Exportable key : {0}" -f [bool]$wiz.ExportableKey)
    Write-Host ("  Enroll ->      : {0}" -f $(if ($wiz.EnrollPrincipal) { $wiz.EnrollPrincipal } else { '(none yet - skip for now)' }))
    Write-Host ""
    # Same idempotency reasoning as menu 4's batch create/publish prompt above - safe to default Yes.
    if (-not (Read-CAConfirm -Prompt "Create/publish this template now?" -DefaultYes)) {
        Read-Host "`nPress Enter to return to the menu" | Out-Null
        return
    }

    try {
        $cn = New-CAVpnTemplate -Spec $spec
        if ($wiz.EnrollPrincipal) {
            Grant-CATemplateEnrollment -TemplateInternalName $cn -PrincipalName $wiz.EnrollPrincipal
        }
        Add-CAPublishedTemplate -TemplateName @($cn)
        Write-Host ""
        Write-Host "  Done. Check with:  certutil -CATemplates" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    try { Remove-CAOrphanTemplateOids | Out-Null } catch { }
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}

function Invoke-CAMenuUmbrella {
    param($CAAnswers)
    Write-CAHeader "Set template permissions (auto-enrollment umbrella group)"
    $dn = Resolve-CAUmbrellaGroup -SuggestedName $CAAnswers.CA_AutoEnrollGroup
    if ($dn) {
        Write-Host ""
        Write-Host "Umbrella group: $dn" -ForegroundColor Green
        Write-Host "Template creation already granted this group (and the others) Enroll on their" -ForegroundColor Gray
        Write-Host "matching templates. AutoEnroll is a separate, deliberate switch now - see the" -ForegroundColor Gray
        Write-Host "enrollment gate menu item to turn it on (or off) per group, whenever you're ready." -ForegroundColor Gray
        if ($CAAnswers -and -not $CAAnswers.CA_AutoEnrollGroup) {
            $name = ($dn -split ',')[0] -replace '^CN='
            $CAAnswers | Add-Member -NotePropertyName CA_AutoEnrollGroup -NotePropertyValue $name -Force
        }
    }
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}

function Resolve-CAAutoEnrollGatePrincipal {
    <#
    .SYNOPSIS
        Maps an AutoEnrollPrincipals token ('Umbrella' / 'OcspResponderHost' / 'GroupSpecific' /
        'DomainAndEnterpriseAdmins' / a literal name) to an actual DOMAIN\name, mirroring the exact
        switch Invoke-CAMenuTemplates uses for EnrollPrincipals - the gate has to resolve to the SAME
        principal that got Enroll at creation time, or toggling it means nothing.
    #>
    param($Token, $Spec, $CAAnswers)
    switch ($Token) {
        'Umbrella'                  { $CAAnswers.CA_AutoEnrollGroup }
        'OcspResponderHost'         { Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_OcspResponderHost' -Prompt "OCSP responder host/group (DOMAIN\name)" -Remember }
        'GroupSpecific'             { $Spec.GroupName }
        'DomainAndEnterpriseAdmins' { $null }   # already enrolled via inherited ACEs - nothing to gate
        default                    { $Token }
    }
}

function Invoke-CAMenuAutoEnrollGate {
    <#
    .SYNOPSIS
        "The enrollment gate" - lists every template that's SUPPOSED to auto-enroll someone
        (AutoEnrollPrincipals non-empty in Get-CATemplateSpecForAnswers) alongside whether that
        principal currently holds the AutoEnroll ACE, and lets the operator flip it on/off per row.
        Template creation (menu 4) only ever grants Enroll now - this is the one place AutoEnroll
        actually gets turned on, deliberately, decoupled from build order.
    #>
    param($CAAnswers, $Status)
    while ($true) {
        Write-CAHeader "The enrollment gate (AutoEnroll on/off, per group)"
        $spec = @(Get-CATemplateSpecForAnswers -CAAnswers $CAAnswers | Where-Object { $_.AutoEnrollPrincipals -and $_.AutoEnrollPrincipals.Count })
        if (-not $spec.Count) {
            Write-Host "  No templates in the current plan have an AutoEnroll principal configured - nothing to gate." -ForegroundColor Gray
            Read-Host "`nPress Enter to return to the menu" | Out-Null
            return
        }

        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($t in $spec) {
            $cn = ($t.DisplayName -replace '[^A-Za-z0-9]', '')
            foreach ($p in $t.AutoEnrollPrincipals) {
                $who = Resolve-CAAutoEnrollGatePrincipal -Token $p -Spec $t -CAAnswers $CAAnswers
                if ([string]::IsNullOrWhiteSpace($who)) { continue }
                $on = $false
                try { $on = Test-CATemplateAutoEnroll -TemplateInternalName $cn -PrincipalName $who } catch { }
                $rows.Add([pscustomobject]@{ DisplayName = $t.DisplayName; Cn = $cn; Principal = $who; Enabled = $on })
            }
        }
        if (-not $rows.Count) {
            Write-Host "  Every AutoEnroll principal above is blank (umbrella group not set yet, etc.) - nothing to gate." -ForegroundColor Gray
            Read-Host "`nPress Enter to return to the menu" | Out-Null
            return
        }

        Write-Host ""
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            $state = if ($r.Enabled) { "ON " } else { "off" }
            $color = if ($r.Enabled) { 'Green' } else { 'DarkGray' }
            Write-Host ("  {0}. [{1}] {2,-30} -> {3}" -f ($i + 1), $state, $r.DisplayName, $r.Principal) -ForegroundColor $color
        }
        Write-Host ""
        Write-Host "  Enter a number to toggle that row, or Enter to return to the menu." -ForegroundColor Gray
        $pick = Read-Host "Choice"
        if ([string]::IsNullOrWhiteSpace($pick)) { return }
        $idx = 0
        if (-not [int]::TryParse($pick, [ref]$idx) -or $idx -lt 1 -or $idx -gt $rows.Count) {
            Write-Host "  Not a valid row number." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            continue
        }
        $row = $rows[$idx - 1]
        $newState = -not $row.Enabled
        $verb = if ($newState) { 'GRANT' } else { 'REVOKE' }
        Write-Host ""
        Write-Host "  $verb AutoEnroll for $($row.Principal) on $($row.DisplayName) (CN=$($row.Cn))" -ForegroundColor $(if ($newState) { 'Yellow' } else { 'Yellow' })
        if (Read-CAConfirm -Prompt "Proceed?") {
            try {
                Set-CATemplateAutoEnroll -TemplateInternalName $row.Cn -PrincipalName $row.Principal -Enabled $newState
                Write-Host "  Done." -ForegroundColor Green
            } catch {
                Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
            }
            Start-Sleep -Seconds 1
        }
    }
}

function Invoke-CAMenuUrls {
    param($CAAnswers, $Status)
    Write-CAHeader "Route AIA / CDP / OCSP through the App Proxy"
    $crlFqdn  = Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_AppProxyCrlFqdn'  -Prompt "App Proxy external hostname for CRL/AIA" -Remember
    $ocspFqdn = Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_AppProxyOcspFqdn' -Prompt "App Proxy external hostname for OCSP" -Remember
    $delta = -not ($CAAnswers.CA_DeltaCrl -match '^(?i)n')
    $sharePath = if ($CAAnswers.CA_CrlShareMode -and $CAAnswers.CA_CrlShareMode -notmatch '^(?i)none') { $CAAnswers.CA_CrlSharePath } else { $null }

    $plan = Get-CAPublicationUrlPlan -CrlFqdn $crlFqdn -OcspFqdn $ocspFqdn -DeltaCrl $delta -CrlSharePath $sharePath
    Write-Host ""
    Write-Host "  CDP (CRLPublicationURLs):" -ForegroundColor White
    foreach ($e in $plan.Cdp) { Write-Host "    $e" -ForegroundColor Gray }
    Write-Host "  AIA (CACertPublicationURLs):" -ForegroundColor White
    foreach ($e in $plan.Aia) { Write-Host "    $e" -ForegroundColor Gray }
    Write-Host ""
    Write-Host "  ORDER-CRITICAL: run this BEFORE any certificate is issued - issued certs bake these URLs in." -ForegroundColor Yellow
    if (Read-CAConfirm -Prompt "`nApply (certutil -setreg + republish CRL + restart CertSvc)?") {
        Set-CAPublicationUrls -Plan $plan
    }
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}

function Invoke-CAMenuAppProxy {
    <#
    .SYNOPSIS
        Menu 6 (2026-09-10 renumber - was menu 7). IIS /CertEnroll/ + the Entra private-network
        connector + connector group + the CRL and OCSP App Proxy apps. Steps 6a-6f, guided, every
        mutation dry-run aware. Resolves the
        real *.msappproxy.net hostnames and writes them back onto $CAAnswers (persisted by the
        dashboard) so menu 8 can route the CA's CDP/AIA/OCSP at them.
    #>
    param($CAAnswers, $Status)
    Write-CAHeader "App Proxy connector + Entra apps"

    Write-Host "  This runs BEFORE menu 8 and before any certificate is issued: menu 8 bakes the"     -ForegroundColor Yellow
    Write-Host "  external hostnames resolved here into every issued cert's CDP/AIA/OCSP URLs."       -ForegroundColor Yellow

    # IE Enhanced Security Configuration makes the Graph sign-in AND the connector installer's
    # modern-auth window go blank on a server. Offer to turn it off up front.
    $esc = Get-CAIEEnhancedSecurity
    if ($esc.Admin -eq $true -or $esc.User -eq $true) {
        Write-Host ""
        Write-Host "  IE Enhanced Security Configuration is ON. The Graph sign-in and the connector" -ForegroundColor Yellow
        Write-Host "  installer's auth window can come up blank because of it." -ForegroundColor Yellow
        if (Read-CAConfirm -Prompt "  Turn IE ESC OFF now (explorer restarts briefly; re-enable later via menu 6 or Server Manager)?" -DefaultYes) {
            Set-CAIEEnhancedSecurity -Enabled $false
        }
    }

    # --- 6a  connect + context -------------------------------------------------
    # Back-navigation (2026-09-10, Part A item 3): only these 3 prompts get it, not the rest of this
    # wizard - 6b onward interleaves prompts with real mutating actions (IIS config, connector
    # install, Graph app publish), and "go back" can't undo an already-applied step, so offering it
    # there would be misleading. This trio is a genuine undo-able sequence with nothing mutating yet.
    $steps = @(
        @{ Name = 'GrpName'; Run = {
            param($CanGoBack)
            Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_AppProxyConnectorGroup' -Prompt "Connector group name" -Remember -AllowBack:$CanGoBack
        } }
        @{ Name = 'CrlAppName'; Run = {
            param($CanGoBack)
            Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_AppProxyCrlAppName' -Prompt "CRL app display name" -Remember -AllowBack:$CanGoBack
        } }
        @{ Name = 'OcspAppName'; Run = {
            param($CanGoBack)
            Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_AppProxyOcspAppName' -Prompt "OCSP app display name" -Remember -AllowBack:$CanGoBack
        } }
    )
    $wiz6a = Invoke-CAWizardSteps -Steps $steps
    $grpName = $wiz6a.GrpName

    Write-Host ""
    Write-Host "  Signing in to Microsoft Graph (Application Administrator)..." -ForegroundColor Gray
    $ctx = Connect-CAGraph
    if (-not $ctx) { Read-Host "`nPress Enter to return to the menu" | Out-Null; return }

    $missing = Test-CAGraphWriteScopes
    if ($missing.Count) {
        Write-Host "  WARNING: the sign-in is missing write scopes: $($missing -join ', ')" -ForegroundColor Yellow
        Write-Host "  Re-run and consent, or sign in as an account that can grant them." -ForegroundColor Yellow
        if (-not (Read-CAConfirm -Prompt "  Continue anyway?" )) { Read-Host "`nPress Enter to return to the menu" | Out-Null; return }
    }

    $tenantLabel = if ($CAAnswers.CA_MsAppProxyTenant) { $CAAnswers.CA_MsAppProxyTenant } else { Get-CAGraphTenantInitialDomain }
    if ([string]::IsNullOrWhiteSpace($tenantLabel)) {
        $tenantLabel = Read-CANonEmpty -Prompt "  msappproxy tenant label (the bit before .onmicrosoft.com)"
    }
    Write-Host ("  Tenant label for *.msappproxy.net hostnames: {0}" -f $tenantLabel) -ForegroundColor Green
    if (-not (Read-CAConfirm -Prompt "  Use it?" -DefaultYes)) {
        $tenantLabel = Read-CANonEmpty -Prompt "  msappproxy tenant label"
    }
    if ($CAAnswers -and -not $CAAnswers.CA_MsAppProxyTenant) {
        $CAAnswers | Add-Member -NotePropertyName CA_MsAppProxyTenant -NotePropertyValue $tenantLabel -Force
    }

    $caHost = try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { "$env:COMPUTERNAME" }
    Write-Host ("  This CA's internal FQDN (App Proxy backend): {0}" -f $caHost) -ForegroundColor Green
    if (-not (Read-CAConfirm -Prompt "  Correct?" -DefaultYes)) { $caHost = Read-CANonEmpty -Prompt "  CA internal FQDN" }

    Write-Host ""
    Write-Host "  Existing App Proxy objects in this tenant:" -ForegroundColor Gray
    foreach ($g in @(Get-CAGraphAll "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups" -Quiet)) {
        Write-Host ("    group     : {0}" -f $g.name) -ForegroundColor DarkGray
    }
    foreach ($c in @(Get-CAGraphAll "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectors" -Quiet)) {
        Write-Host ("    connector : {0}  ({1})" -f $c.machineName, $c.status) -ForegroundColor DarkGray
    }

    # --- 6b  IIS /CertEnroll/ ------------------------------------------------
    $physPath = if ($CAAnswers.CA_CrlShareMode -and $CAAnswers.CA_CrlShareMode -notmatch '^(?i)none' -and $CAAnswers.CA_CrlSharePath) {
        $CAAnswers.CA_CrlSharePath
    } else { '%windir%\System32\CertSrv\CertEnroll' }
    $webPlan = Get-CAWebEndpointPlan -PhysicalPath $physPath -CACommonName $Status.CACommonName
    Show-CAWebEndpointPlan -Plan $webPlan
    if (Read-CAConfirm -Prompt "`nConfigure the IIS /CertEnroll/ endpoint now?" -DefaultYes) {
        Set-CAWebEndpoint -Plan $webPlan
    }

    # --- 6c  connector install + register ----------------------------------
    Write-Host ""
    if ($Status.AppProxyConnectorInstalled -and $Status.AppProxyConnectorStatus -eq 'Running' -and (Get-CAAppProxyConnector -MachineName $caHost)) {
        Write-Host "  Connector already installed, running, and registered - skipping 7c." -ForegroundColor Green
    } elseif (Read-CAConfirm -Prompt "Install + register the Entra private-network connector on this box?" -DefaultYes) {
        Write-Host "  Tip: the surest source is the Entra admin center -> Enterprise applications -> Application" -ForegroundColor DarkGray
        Write-Host "       proxy -> Download connector service. Auto-download tries the tenant URL + aka.ms links." -ForegroundColor DarkGray
        $preDl = Read-Host "  Path to a pre-downloaded connector .exe (blank = auto-download)"
        if ([string]::IsNullOrWhiteSpace($preDl)) {
            Install-CAAppProxyConnector -TenantId $ctx.TenantId
        } else {
            Install-CAAppProxyConnector -TenantId $ctx.TenantId -InstallerPath $preDl.Trim('"')
        }
        Repair-CAModulePath   # the connector installer rewrites PSModulePath and drops the CurrentUser path
    }

    # --- 6d  connector group ---------------------------------------------------
    Write-Host ""
    $groupId = New-CAAppProxyConnectorGroup -Name $grpName
    $conn = Get-CAAppProxyConnector -MachineName $caHost
    if (-not $conn -and (Get-CADryRun)) { $conn = [pscustomobject]@{ id = '<connectorId>' } }   # so the memberOf step previews
    if ($groupId -and $conn) {
        Add-CAAppProxyConnectorToGroup -ConnectorId $conn.id -GroupId $groupId
    } elseif (-not (Get-CADryRun)) {
        Write-Host "  Could not resolve the connector or group id - finish 6c, then re-run menu 6." -ForegroundColor Yellow
    }

    # --- 6e  the two apps ----------------------------------------------------
    $appPlan = Get-CAAppProxyPlan -CAAnswers $CAAnswers -CAHostFqdn $caHost -TenantLabel $tenantLabel
    Show-CAAppProxyPlan -Plan $appPlan
    Write-Host ""
    Write-Host "  Note: the OCSP app's /ocsp/ backend does not exist until menu 9 (Online Responder)." -ForegroundColor DarkYellow
    $results = @()
    if (Read-CAConfirm -Prompt "Create / update the CRL and OCSP-Relay apps?" -DefaultYes) {
        foreach ($spec in $appPlan.Apps) {
            Write-Host ""
            Write-Host "  --- $($spec.DisplayName) ---" -ForegroundColor Cyan
            try   { $results += Publish-CAAppProxyApp -AppSpec $spec -GroupId $groupId }
            catch { Write-Host "  ERROR on $($spec.DisplayName): $($_.Exception.Message)" -ForegroundColor Red }
        }
    }

    # --- 6f  write-back ----------------------------------------------------
    Write-Host ""
    Write-Host "  External hostnames:" -ForegroundColor Yellow
    foreach ($r in $results) {
        Write-Host ("    {0,-11} {1}" -f $r.Key, $r.ActualExternalUrl) -ForegroundColor Yellow
        if ($r.ActualHost -and $CAAnswers) {
            $field = if ($r.Key -eq 'CRL') { 'CA_AppProxyCrlFqdn' } else { 'CA_AppProxyOcspFqdn' }
            $CAAnswers | Add-Member -NotePropertyName $field -NotePropertyValue $r.ActualHost -Force
        }
    }
    Write-Host ""
    Write-Host "  These are now on the in-memory answers. Re-run menu 8 (Route AIA/CDP/OCSP through the" -ForegroundColor Yellow
    Write-Host "  App Proxy) so the CA bakes them into issued certs - BEFORE issuing anything." -ForegroundColor Yellow

    Read-Host "`nPress Enter to return to the menu" | Out-Null
}

function Invoke-CAMenuOcsp {
    <#
    .SYNOPSIS
        Menu 9 (2026-09-10 renumber - was menu 4). Installs the Online Responder role and creates ONE
        revocation configuration for the local single-tier CA, so http://<host>/ocsp answers (and the
        Menu-6 OCSP-Relay app stops 502ing). Every mutation is dry-run aware; the signing-cert
        acquisition is a non-fatal nudge.
    #>
    param($CAAnswers, $Status)
    Write-CAHeader "Install / configure OCSP (Online Responder)"

    if (-not $Status.CACommonName) {
        Write-Host "  No local CA detected - run menu 9 on the CA box." -ForegroundColor Yellow
        Read-Host "`nPress Enter to return to the menu" | Out-Null; return
    }

    if ($Status -and -not ($Status.HasExternalCDP -and $Status.HasExternalAIAorOCSP)) {
        Write-Host "  NOTE: menu 8 (URL routing) hasn't run - the OCSP signing cert enrolled here will" -ForegroundColor DarkYellow
        Write-Host "  carry the CA's current (non-App-Proxy) URLs. It's 14-day / auto-renewed so it" -ForegroundColor DarkYellow
        Write-Host "  self-corrects, and it has ocsp-nocheck anyway - but running menu 8 first is tidier." -ForegroundColor DarkYellow
        Write-Host ""
    }

    $caFqdn = try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { "$env:COMPUTERNAME" }
    if (-not (Read-CAConfirm -Prompt "  This CA / responder FQDN is '$caFqdn' - correct?" -DefaultYes)) {
        $caFqdn = Read-CANonEmpty -Prompt "  CA / responder FQDN"
    }
    $sanitized = try { Get-CAActiveConfigName } catch { $Status.CACommonName }
    $configNC  = try { Get-CAConfigNamingContext } catch { $null }
    $null      = Get-CAAnswerOrPrompt -CAAnswers $CAAnswers -Field 'CA_TemplateOcspSigning' -Prompt "OCSP response-signing template display name" -Remember
    $delta     = -not ($CAAnswers.CA_DeltaCrl -match '^(?i)n')

    $plan = Get-CAOcspPlan -CAAnswers $CAAnswers -CACommonName $Status.CACommonName `
        -CAMachineFqdn $caFqdn -CASanitizedName $sanitized -ConfigNC $configNC -DeltaCrl $delta
    Show-CAOcspPlan -Plan $plan

    $t = Test-CAOcsp -Plan $plan -ExpectedConfigName $plan.ConfigName -ExpectedCAConfig $plan.CAConfig
    Write-Host ""
    Write-Host ("  Current: role {0}, service {1}, /ocsp {2}, revocation config {3}, signing cert {4}" -f `
        $t.RoleInstalled, $t.ServiceRunning, $t.IsapiAppPresent, $t.RevocationConfigForThisCA, $t.SigningCertAcquired) -ForegroundColor Gray

    if (Read-CAConfirm -Prompt "`nInstall the Online Responder role (if needed) and create this revocation configuration?" -DefaultYes) {
        Install-CAOcspRole
        New-CAOcspRevocationConfig -Plan $plan
        Confirm-CAOcspSigningCertificate -Plan $plan
        Set-CAOcspAuditing -Plan $plan
        Set-CAOcspWebRequestLimits -Plan $plan

        if (-not (Get-CADryRun)) {
            Write-Host "`n  Waiting for the /ocsp proxy to pick up the config..." -ForegroundColor DarkGray
            # transient HTTP 500 (E_FAIL) for ~15s after OCSPSvc reloads - poll past it
            [void](Test-CAOcspEndpoint -Url $plan.LocalVerifyUrl -RetrySeconds 45)
        }

        $t2 = Test-CAOcsp -Plan $plan -ExpectedConfigName $plan.ConfigName -ExpectedCAConfig $plan.CAConfig
        Write-Host ""
        if ($t2.Working) {
            Write-Host "  OCSP responder is Working - $($plan.ResponderUrl) answers for $($plan.CAConfig)." -ForegroundColor Green
        } else {
            Write-Host "  Not fully Working yet:" -ForegroundColor Yellow
            Write-Host ("    service {0} / config-for-this-CA {1} / signing cert {2} / endpoint {3}" -f `
                $t2.ServiceRunning, $t2.RevocationConfigForThisCA, $t2.SigningCertAcquired, $t2.EndpointAnswers) -ForegroundColor Yellow
        }
        Write-Host ("  Hardening: auditing {0} (AuditFilter={1}) / IIS request limits {2} (maxUrl={3}, maxQueryString={4})" -f `
            $t2.AuditFilterOk, $t2.AuditFilterValue, $t2.IisLimitsOk, $t2.IisMaxUrlBytes, $t2.IisMaxQueryStringBytes) -ForegroundColor $(if ($t2.AuditFilterOk -and $t2.IisLimitsOk) { 'Gray' } else { 'DarkYellow' })
    }
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}

# ---------------------------------------------------------------------------
# All numbered menus are wired (2026-09-12 renumber - old menu 10, the auto-enroll GPO push, MOVED
# to the new AD-Manager tool and is no longer part of this dashboard at all): 1 CACore prereqs,
# 2 CAInstall, 3 CATameMyCerts, 4/5 CATemplates, 6 CAAppProxy, 7 CACrlShare, 8 CAUrls, 9 CAOcsp,
# 10 CAHealth, 11 CATestSuite, 12 CARenewalTest, 13 CAFortiGateHandoff, 14 the inventory report,
# 15 the enrollment gate (CATemplates), 16 the ad-hoc template wizard (CATemplates). Sub-CA install
# path is still deferred (Get-CAInstallPlan throws).

# ---------------------------------------------------------------------------
function Show-CAMenuHelp {
    <#
    .SYNOPSIS
        The longer rationale prose that used to live inline, next to every menu item, before the
        2026-09-10 terse/verbose pass (Part A item 6 - The maintainer: "I like the '?' for more info").
        CA-Manager.ps1 shows this automatically once per session (first render), then only on demand
        when the operator presses '?' - the numbered menu itself stays one line per item, matching
        NPS-Manager.ps1's own terse dashboard style.

        2026-09-14: re-numbered throughout for the 2026-09-12 renumber (old menu 10, the GPO push,
        is gone - Toolkit shifted down by one) and gained its own "AD-Manager" section - this help
        screen is CA-Manager's single most-read piece of prose, so it's the right place for a tech to
        actually learn the sibling tool exists, not just infer it from a stray fix-suggestion string.
    #>
    Write-Host ""
    Write-Host "  --- Why this order? ---" -ForegroundColor DarkCyan
    Write-Host "  Setup's order (1-9) only reflects genuine AD/technical dependencies now, not a" -ForegroundColor Gray
    Write-Host "  'must happen in exactly this sequence or you'll get a bad first cert' requirement -" -ForegroundColor Gray
    Write-Host "  that job belongs to item 15 alone (see below). Still, a sensible first pass:" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    1  2  [3]  4  5  ->  6  ->  [7]  ->  8  ->  9  ->  10  ->  [11]  ->  13" -ForegroundColor Gray
    Write-Host "    ([3]/[7]/[11] optional - TameMyCerts / split-tier CRL share / test certs)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    - 4 creates templates, granting Enroll only (never AutoEnroll any more)" -ForegroundColor DarkGray
    Write-Host "    - 8 needs 6's resolved *.msappproxy.net hostnames (and 7's share path, if split-tier)" -ForegroundColor DarkGray
    Write-Host "      before it can route AIA/CDP/OCSP correctly - do it before any cert is issued," -ForegroundColor DarkGray
    Write-Host "      since every issued cert bakes in whatever URLs were live at the time" -ForegroundColor DarkGray
    Write-Host "    - 9 (OCSP) after 8, so the responder's own signing cert gets the right URLs too" -ForegroundColor DarkGray
    Write-Host "    - the auto-enrollment GPO itself now lives in AD-Manager (see below), not here -" -ForegroundColor DarkGray
    Write-Host "      link it whenever's convenient, since nothing actually auto-enrolls until 15 is" -ForegroundColor DarkGray
    Write-Host "      flipped on for a given group" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  --- The enrollment gate (15) ---" -ForegroundColor DarkCyan
    Write-Host "  Enroll and AutoEnroll are deliberately separate now. Item 4 grants Enroll once, at" -ForegroundColor Gray
    Write-Host "  creation, permanently. AutoEnroll is a dedicated on/off switch, per group, at item" -ForegroundColor Gray
    Write-Host "  15 - nothing auto-enrolls for real until you flip it there, verified clean via 10" -ForegroundColor Gray
    Write-Host "  (health check) first. That's what makes the Setup order above safe to revisit out" -ForegroundColor Gray
    Write-Host "  of sequence - not the order itself." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  --- Rollout (17) ---" -ForegroundColor DarkCyan
    Write-Host "  Once Setup is done: batch-issue PFX files for vendors from the manual-approval" -ForegroundColor Gray
    Write-Host "  templates - one output folder and run password per batch, template/user/password per" -ForegroundColor Gray
    Write-Host "  vendor, then one approval pass in certsrv.msc. Nothing is remembered between runs." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  --- AD-Manager (sibling tool) ---" -ForegroundColor DarkCyan
    Write-Host "  PushableTools\ADManager\ handles AD/GPO scaffolding this dashboard used to do a piece" -ForegroundColor Gray
    Write-Host "  of and never fully owned: standing up a client's VPN group/OU structure (main group +" -ForegroundColor Gray
    Write-Host "  the VPNFW purpose groups), pushing/relinking the certificate auto-enrollment GPO" -ForegroundColor Gray
    Write-Host "  (moved there outright, 2026-09-12 - it's no longer a menu item here at all), and the" -ForegroundColor Gray
    Write-Host "  well-known WMI filters. Reach for it before item 5 (the umbrella/permissions group) if" -ForegroundColor Gray
    Write-Host "  the group structure a client needs doesn't exist yet - it's the fuller, OU-aware tool" -ForegroundColor Gray
    Write-Host "  for that, not a one-off typed group name." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Press '?' any time to see this again; Enter to dismiss." -ForegroundColor DarkGray
    Read-Host | Out-Null
}

# ---------------------------------------------------------------------------
function Test-CAHelpAcknowledged {
    <#
    .SYNOPSIS
        Whether this box has already acknowledged the "why this order?" intro (CA_HelpAcknowledged =
        Yes in CAAnswers.json) - PERSISTED, not per-session. 2026-09-11, per the maintainer: the old
        $script:CAHelpShownThisSession flag reset on every relaunch, so the intro reappeared every
        single time (including via the new menu-1 "relaunch CA-Manager" flow) - annoying on a box a
        tech is already familiar with. Read-only; pairs with Set-CAHelpAcknowledged below.
    #>
    param($CAAnswers)
    [bool]($CAAnswers -and $CAAnswers.PSObject.Properties['CA_HelpAcknowledged'] -and "$($CAAnswers.CA_HelpAcknowledged)" -match '^(?i)y')
}

function Set-CAHelpAcknowledged {
    <#
    .SYNOPSIS
        Records that this box has seen the intro, writing CAAnswers.json DIRECTLY - deliberately NOT
        through Invoke-CAStep/Save-CAAnswers. CA-Manager starts every session in DRY RUN by default,
        and Invoke-CAStep never runs its -Action in DRY RUN - routing this through the normal
        Save-CAAnswers path would mean the very first session (the one where the intro actually shows)
        can never actually persist the acknowledgment, defeating the whole point. This is tool-UX
        preference state, not a mutation of the target CA/AD environment - the DRY RUN gate exists to
        protect the latter, not the former, so bypassing it here is deliberate, not an oversight.
        Serializes with the exact same shape Save-CAAnswers uses (ConvertTo-Json -Depth 6, CRLF-
        normalized, UTF8) so the two writers never fight over file format.
    .OUTPUTS
        The (possibly newly-created) $CAAnswers object, so the caller's own variable stays in sync -
        PowerShell hashtables/pscustomobjects are reference types for in-place property sets, but a
        caller starting from $null needs the new object handed back explicitly.
    #>
    param($CAAnswers, [Parameter(Mandatory)][string]$Path)
    if (-not $CAAnswers) { $CAAnswers = [pscustomobject]@{} }
    if ($CAAnswers.PSObject.Properties['CA_HelpAcknowledged']) { $CAAnswers.CA_HelpAcknowledged = 'Yes' }
    else { $CAAnswers | Add-Member -NotePropertyName CA_HelpAcknowledged -NotePropertyValue 'Yes' -Force }
    try {
        $json = $CAAnswers | ConvertTo-Json -Depth 6
        $json = ($json -replace "`r`n", "`n") -replace "`n", "`r`n"
        Set-Content -Path $Path -Value $json -Encoding UTF8
    } catch {
        Write-Host "  WARNING: could not save CA_HelpAcknowledged to $Path ($($_.Exception.Message)) - the intro will show again next launch." -ForegroundColor Yellow
    }
    return $CAAnswers
}
