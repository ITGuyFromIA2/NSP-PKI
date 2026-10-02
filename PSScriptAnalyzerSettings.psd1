@{
    # NSP house lint config. Referenced by tools\Test-Repo.ps1 and by editor integrations.
    IncludeDefaultRules = $true
    Severity            = @('Error', 'Warning')

    ExcludeRules = @(
        # Interactive operator tooling - coloured status output via Write-Host is deliberate.
        'PSAvoidUsingWriteHost'

        # New-/Set-/Reset- helpers that only build objects or text trip this heuristic; functions
        # that genuinely change state declare SupportsShouldProcess.
        'PSUseShouldProcessForStateChangingFunctions'

        # Fires on the shared test harness (Assert-Contains, Reset-TestCounters, ...), a canonical
        # copy synced from NSP-Bootstrap - not edited per-repo.
        'PSUseSingularNouns'
    )
}