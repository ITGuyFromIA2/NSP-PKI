<#
    Pester 5. This repo's Private\Import-NSPToolkitModule.ps1 is a generated copy of NSP-Toolkit's
    canonical loader (NSP-Toolkit\tools\Sync-SharedLoader.ps1). Skipped when NSP-Toolkit isn't
    checked out next to this repository.
#>

Describe 'Shared sibling loader copy' {
    It 'matches the canonical copy in NSP-Toolkit' {
        $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $canonical = Join-Path $root 'NSP-Toolkit\Private\Import-NSPToolkitModule.ps1'
        if (-not (Test-Path -LiteralPath $canonical)) { Set-ItResult -Skipped -Because 'NSP-Toolkit is not checked out next to this repository'; return }
        $mine = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $PSScriptRoot) 'Private\Import-NSPToolkitModule.ps1')) -replace "`r?`n", "`r`n"
        $mine | Should -BeExactly ([IO.File]::ReadAllText($canonical) -replace "`r?`n", "`r`n") -Because 'run NSP-Toolkit\tools\Sync-SharedLoader.ps1 - do not edit the copy'
    }
}