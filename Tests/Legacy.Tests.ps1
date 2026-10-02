<#
    Pester 5 wrapper for the tests ported from NSP-FGTIPSecTools (Tests\Legacy\*.LegacyTest.ps1, the repo's
    own AST-extraction harness). Each runs in a child PowerShell of the same edition and must exit 0.
#>
Describe 'Ported NSP-FGTIPSecTools tests' {
    $legacy = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Legacy') -Filter '*.LegacyTest.ps1' | ForEach-Object { @{ Name = $_.BaseName; Path = $_.FullName } })
    It '<Name>' -ForEach $legacy {
        $exe = (Get-Process -Id $PID).Path
        $out = & $exe -NoProfile -ExecutionPolicy Bypass -File $Path 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0 -Because $out
    }
}