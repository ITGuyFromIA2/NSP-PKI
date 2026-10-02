<#
    Pester 5. Module hygiene: manifest valid, imports clean, exports match the manifest, every
    exported function has a synopsis and an example.
#>

$script:ManifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.PKI.psd1'
Import-Module $script:ManifestPath -Force -ErrorAction Stop

BeforeAll {
    $script:ManifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.PKI.psd1'
    Import-Module $script:ManifestPath -Force -ErrorAction Stop
}

Describe 'NSP.PKI manifest' {
    It 'has a valid module manifest' {
        { Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }
    It 'targets Windows PowerShell 5.1 as the floor' {
        (Test-ModuleManifest -Path $ManifestPath).PowerShellVersion | Should -Be ([version]'5.1')
    }
    It 'declares no RequiredModules (must import on a bare 5.1 host)' {
        (Test-ModuleManifest -Path $ManifestPath).RequiredModules.Count | Should -Be 0
    }
    It 'exports exactly the functions listed in the manifest' {
        $manifestFns = @((Import-PowerShellDataFile $ManifestPath).FunctionsToExport | Sort-Object)
        $actualFns   = @((Get-Command -Module NSP.PKI -CommandType Function).Name | Sort-Object)
        $actualFns | Should -Be $manifestFns
    }
}

Describe 'NSP.PKI exported help' {
    $exported = @((Get-Command -Module NSP.PKI -CommandType Function).Name)
    It '<_> has a synopsis' -ForEach $exported {
        (Get-Help $_ -ErrorAction SilentlyContinue).Synopsis.Trim() | Should -Not -BeNullOrEmpty
    }
    It '<_> has at least one example' -ForEach $exported {
        @((Get-Help $_ -ErrorAction SilentlyContinue).Examples.Example).Count | Should -BeGreaterThan 0
    }
}