<#
    Pester 5. VPNCertEval's data-only readers (the rest of the harness is covered by
    Tests\Legacy\VPNCertEval.LegacyTest.ps1): the unit-tests file parser evaluates literals only
    (it used to fall back to Invoke-Expression), and the site-specific RDP name map is read as data.
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'Scripts\VPNCertEval\VPNCertEval.Common.ps1')

    function New-UnitTestsFile([string]$Body) {
        $path = Join-Path $TestDrive ('UnitTests_' + [guid]::NewGuid().ToString('N') + '.ps1')
        Set-Content -LiteralPath $path -Value $Body -Encoding UTF8
        return $path
    }
}

Describe 'ConvertFrom-UnitTestsFile' {
    It 'reads $Endpoints and $ServiceChecks literals without running the rest of the file' {
        $sentinel = Join-Path $TestDrive 'ran.txt'
        $path = New-UnitTestsFile @"
Set-Content -LiteralPath '$sentinel' -Value 'the file body ran'
`$Endpoints = [ordered]@{
    'FS01.contoso.com' = @('SMB', 'RDP')
    'DC01.contoso.com' = @('DNS')
}
`$ServiceChecks = @{ SMB = @{ Port = 445; Enabled = `$true; Offset = -1; Note = "plain" } }
"@
        $r = ConvertFrom-UnitTestsFile -Path $path
        @($r.Endpoints.Keys) | Should -Be @('FS01.contoso.com', 'DC01.contoso.com')
        $r.Endpoints['FS01.contoso.com'] | Should -Be @('SMB', 'RDP')
        $r.ServiceChecks.SMB.Port | Should -Be 445
        $r.ServiceChecks.SMB.Enabled | Should -BeTrue
        $r.ServiceChecks.SMB.Offset | Should -Be -1
        Test-Path -LiteralPath $sentinel | Should -BeFalse
    }

    It 'returns $null for a variable the file does not assign' {
        (ConvertFrom-UnitTestsFile -Path (New-UnitTestsFile '$Endpoints = @{}')).ServiceChecks | Should -BeNullOrEmpty
    }

    It 'refuses <Case> and runs nothing' -TestCases @(
        @{ Case = 'a command';            Value = '@{ A = (New-Item -ItemType File -Path "SENTINEL") }' }
        @{ Case = 'a sub-expression';     Value = '@{ A = "x$(New-Item -ItemType File -Path ''SENTINEL'')" }' }
        @{ Case = 'a static method call'; Value = '@{ A = [IO.File]::WriteAllText(''SENTINEL'', ''x'') }' }
        @{ Case = 'a script block';       Value = '@{ A = { New-Item -ItemType File -Path ''SENTINEL'' } }' }
        @{ Case = 'another variable';     Value = '@{ A = $env:TEMP }' }
        @{ Case = 'a cast to a type';     Value = '@{ A = [IO.FileInfo]''SENTINEL'' }' }
    ) {
        $sentinel = Join-Path $TestDrive ('pwned_' + [guid]::NewGuid().ToString('N'))
        $path = New-UnitTestsFile ('$Endpoints = ' + $Value.Replace('SENTINEL', $sentinel))
        { ConvertFrom-UnitTestsFile -Path $path } | Should -Throw '*not a plain data literal*'
        Test-Path -LiteralPath $sentinel | Should -BeFalse
    }
}

Describe 'Get-EvalLocalRdpPattern' {
    AfterEach { Remove-Item Env:\NSP_VPNCERTEVAL_MAP -ErrorAction SilentlyContinue }

    It 'returns $null when there is no local map' {
        $env:NSP_VPNCERTEVAL_MAP = Join-Path $TestDrive 'none.psd1'
        Get-EvalLocalRdpPattern | Should -BeNullOrEmpty
    }

    It 'returns the RdpNamePattern from the map NSP_VPNCERTEVAL_MAP names' {
        $env:NSP_VPNCERTEVAL_MAP = Join-Path $TestDrive 'map.psd1'
        Set-Content -LiteralPath $env:NSP_VPNCERTEVAL_MAP -Value "@{ RdpNamePattern = 'ERPApp|PayrollSrv' }"
        Get-EvalLocalRdpPattern | Should -Be 'ERPApp|PayrollSrv'
    }

    It 'ignores, with a warning, a map whose pattern is not a valid regex' {
        $env:NSP_VPNCERTEVAL_MAP = Join-Path $TestDrive 'bad.psd1'
        Set-Content -LiteralPath $env:NSP_VPNCERTEVAL_MAP -Value "@{ RdpNamePattern = 'ERP(' }"
        $out = @(Get-EvalLocalRdpPattern 3>&1)
        @($out | Where-Object { $_ -isnot [Management.Automation.WarningRecord] -and $null -ne $_ }).Count | Should -Be 0
        "$($out | Where-Object { $_ -is [Management.Automation.WarningRecord] })" | Should -Match 'Ignoring'
    }

    It 'refuses a map that is not plain data' {
        $env:NSP_VPNCERTEVAL_MAP = Join-Path $TestDrive 'code.psd1'
        Set-Content -LiteralPath $env:NSP_VPNCERTEVAL_MAP -Value "@{ RdpNamePattern = (Get-Date).ToString() }"
        Get-EvalLocalRdpPattern 3>$null | Should -BeNullOrEmpty
    }
}
