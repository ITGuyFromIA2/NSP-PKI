<#
    Pester 5. Invoke-CAInstall and Set-CAPublicationUrls, the two functions that create a CA and
    route its publication URLs, with every outside call mocked. Nothing here installs a role, writes
    under the Windows folder, runs certutil or touches a service: each of those is replaced, and the
    tests count the replacements.

    These tests describe what the functions do today. They change no behaviour.
#>

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.PKI.psd1') -Force -ErrorAction Stop

    # Server-only commands do not exist on a workstation, and a command has to exist to be mocked.
    # These stand-ins throw, so a test that forgets a mock fails instead of doing anything.
    $script:StandIns = 'Install-WindowsFeature', 'Install-AdcsCertificationAuthority', 'Get-ADRootDSE', 'Get-ADObject'
    foreach ($name in $script:StandIns) {
        Set-Item -Path "Function:\global:$name" -Value ([scriptblock]::Create("throw 'Stand-in for $name was called without a mock.'"))
    }
    $script:RealWindir = $env:windir
}

AfterAll {
    foreach ($name in $script:StandIns) { Remove-Item -Path "Function:\$name" -ErrorAction SilentlyContinue }
    $env:windir = $script:RealWindir
    Remove-Module NSP.PKI -Force -ErrorAction SilentlyContinue
}

Describe 'Get-CAInstallPlan' {
    It 'asks for an enterprise root on the software key storage provider with a new 4096-bit key' {
        InModuleScope NSP.PKI {
            $plan = Get-CAInstallPlan -CACommonName 'EXAMPLE-ROOT-CA'
            $plan.CAType | Should -Be 'EnterpriseRootCA'
            $plan.CACommonName | Should -Be 'EXAMPLE-ROOT-CA'
            $plan.KeyLength | Should -Be 4096
            $plan.HashAlgorithmName | Should -Be 'SHA256'
            $plan.CryptoProviderName | Should -Be 'RSA#Microsoft Software Key Storage Provider'
            $plan.ValidityPeriod | Should -Be 'Years'
            $plan.ValidityPeriodUnits | Should -Be 10
        }
    }

    It 'never asks the installer to reuse, import or overwrite a key' {
        # Install-AdcsCertificationAuthority can be pointed at an existing key or a certificate file.
        # The plan must not do that: the only key a new CA gets is the one the installer makes.
        InModuleScope NSP.PKI {
            $plan = Get-CAInstallPlan -CACommonName 'EXAMPLE-ROOT-CA'
            foreach ($forbidden in 'KeyContainerName', 'CertFile', 'CertFilePassword', 'CertificateID', 'OverwriteExistingKey', 'OverwriteExistingCAinDS', 'OverwriteExistingDatabase', 'IgnoreUnicode', 'Credential', 'ParentCA', 'OutputCertRequestFile') {
                $plan.ContainsKey($forbidden) | Should -BeFalse -Because "$forbidden must not be passed"
            }
            @($plan.Keys | Sort-Object) | Should -Be @('CACommonName', 'CAType', 'CryptoProviderName', 'Force', 'HashAlgorithmName', 'KeyLength', 'ValidityPeriod', 'ValidityPeriodUnits')
        }
    }

    It 'refuses a subordinate CA' {
        InModuleScope NSP.PKI {
            { Get-CAInstallPlan -CACommonName 'EXAMPLE-SUB-CA' -CAType EnterpriseSubordinateCA } | Should -Throw '*only EnterpriseRootCA*'
        }
    }
}

Describe 'Invoke-CAInstall' {
    BeforeEach {
        # Belt and braces: even if a mock were missed, nothing could be written under the real Windows folder.
        $env:windir = Join-Path $TestDrive ('windir_' + [guid]::NewGuid().ToString('N'))
        $script:Order = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName NSP.PKI Write-Host { }
        Mock -ModuleName NSP.PKI Set-Content { $script:Order.Add('capolicy') }
        Mock -ModuleName NSP.PKI Install-WindowsFeature { $script:Order.Add('feature'); [pscustomobject]@{ RestartNeeded = 'No' } }
        Mock -ModuleName NSP.PKI Import-Module { }
        Mock -ModuleName NSP.PKI Install-AdcsCertificationAuthority { $script:Order.Add('install'); $script:InstallArgumentList = $args }
        Mock -ModuleName NSP.PKI Get-ADRootDSE { [pscustomobject]@{ configurationNamingContext = 'CN=Configuration,DC=example,DC=test' } }
        Mock -ModuleName NSP.PKI Get-ADObject { $null }
        Mock -ModuleName NSP.PKI Read-Host { throw 'must not prompt' }
    }
    AfterEach {
        InModuleScope NSP.PKI { Set-CADryRun -Enabled $true }
        $env:windir = $script:RealWindir
    }

    It 'does nothing in a dry run' {
        InModuleScope NSP.PKI {
            Get-CADryRun | Should -BeTrue
            Invoke-CAInstall -CACommonName 'EXAMPLE-ROOT-CA'
        }
        $Order.Count | Should -Be 0
        Should -Invoke -ModuleName NSP.PKI Set-Content -Times 0 -Exactly
        Should -Invoke -ModuleName NSP.PKI Install-WindowsFeature -Times 0 -Exactly
        Should -Invoke -ModuleName NSP.PKI Install-AdcsCertificationAuthority -Times 0 -Exactly
        Should -Invoke -ModuleName NSP.PKI Import-Module -Times 0 -Exactly
        Should -Invoke -ModuleName NSP.PKI Get-ADObject -Times 0 -Exactly
    }

    It 'writes capolicy.inf, adds the role, then installs, in that order' {
        InModuleScope NSP.PKI {
            Set-CADryRun -Enabled $false
            Invoke-CAInstall -CACommonName 'EXAMPLE-ROOT-CA' -ValidityYears 12 -CrlPeriodDays 5
        }
        ($Order -join ',') | Should -Be 'capolicy,feature,install'
        Should -Invoke -ModuleName NSP.PKI Set-Content -Times 1 -Exactly -ParameterFilter {
            $Path -eq (Join-Path $env:windir 'capolicy.inf') -and "$Encoding" -match 'ASCII' -and
            $Value -match 'RenewalValidityPeriodUnits=12' -and $Value -match 'CRLPeriodUnits=5' -and $Value -match 'LoadDefaultTemplates=0'
        }
        Should -Invoke -ModuleName NSP.PKI Install-WindowsFeature -Times 1 -Exactly
        Should -Invoke -ModuleName NSP.PKI Install-AdcsCertificationAuthority -Times 1 -Exactly
    }

    It 'passes the installer the plan and nothing else' {
        InModuleScope NSP.PKI {
            Set-CADryRun -Enabled $false
            Invoke-CAInstall -CACommonName 'EXAMPLE-ROOT-CA' -ValidityYears 12 -KeyLength 4096
        }
        # The stand-in declares no parameters, so the splatted plan arrives as "-Name: value" pairs.
        $text = @($InstallArgumentList | ForEach-Object { [string]$_ }) -join ' '
        $text | Should -Match '-CAType:? EnterpriseRootCA'
        $text | Should -Match '-CACommonName:? EXAMPLE-ROOT-CA'
        $text | Should -Match '-KeyLength:? 4096'
        $text | Should -Match '-CryptoProviderName:? RSA#Microsoft Software Key Storage Provider'
        $text | Should -Match '-ValidityPeriodUnits:? 12'
        $text | Should -Not -Match '(?i)KeyContainerName|CertFile|CertificateID|OverwriteExisting|ParentCA|Credential'
    }

    It 'stops before the install when the deployment module cannot be loaded' {
        Mock -ModuleName NSP.PKI Import-Module { throw 'module not found' }
        InModuleScope NSP.PKI {
            Set-CADryRun -Enabled $false
            Invoke-CAInstall -CACommonName 'EXAMPLE-ROOT-CA'
        }
        ($Order -join ',') | Should -Be 'capolicy,feature'
        Should -Invoke -ModuleName NSP.PKI Install-AdcsCertificationAuthority -Times 0 -Exactly
    }

    It 'stops before changing anything when the directory already has a CA of that name and the operator declines' {
        Mock -ModuleName NSP.PKI Get-ADObject { [pscustomobject]@{ Name = 'EXAMPLE-ROOT-CA' } }
        Mock -ModuleName NSP.PKI Read-Host { 'no' }
        InModuleScope NSP.PKI {
            Set-CADryRun -Enabled $false
            Invoke-CAInstall -CACommonName 'EXAMPLE-ROOT-CA'
        }
        $Order.Count | Should -Be 0
        Should -Invoke -ModuleName NSP.PKI Read-Host -Times 1 -Exactly
    }

    It 'goes on only when the operator types CONTINUE exactly' {
        Mock -ModuleName NSP.PKI Get-ADObject { [pscustomobject]@{ Name = 'EXAMPLE-ROOT-CA' } }
        Mock -ModuleName NSP.PKI Read-Host { 'continue' }
        InModuleScope NSP.PKI { Set-CADryRun -Enabled $false; Invoke-CAInstall -CACommonName 'EXAMPLE-ROOT-CA' }
        $Order.Count | Should -Be 0

        Mock -ModuleName NSP.PKI Read-Host { 'CONTINUE' }
        InModuleScope NSP.PKI { Invoke-CAInstall -CACommonName 'EXAMPLE-ROOT-CA' }
        ($Order -join ',') | Should -Be 'capolicy,feature,install'
    }

    It 'lets an installer failure reach the caller' {
        Mock -ModuleName NSP.PKI Install-AdcsCertificationAuthority { throw 'The installation failed.' }
        {
            InModuleScope NSP.PKI {
                Set-CADryRun -Enabled $false
                Invoke-CAInstall -CACommonName 'EXAMPLE-ROOT-CA'
            }
        } | Should -Throw '*installation failed*'
    }
}

Describe 'Set-CAPublicationUrls' {
    BeforeEach {
        $script:Calls = New-Object System.Collections.Generic.List[string]
        $script:ExitCodes = @{ setreg = 0; ping = 0; crl = 0 }
        Mock -ModuleName NSP.PKI Write-Host { }
        Mock -ModuleName NSP.PKI Start-Sleep { }
        Mock -ModuleName NSP.PKI Restart-Service { $script:Calls.Add('restart ' + $Name) }
        Mock -ModuleName NSP.PKI certutil.exe {
            $verb = ([string]$args[0]).TrimStart('-')
            $script:Calls.Add(($args | ForEach-Object { [string]$_ }) -join ' ')
            $global:LASTEXITCODE = $script:ExitCodes[$verb]
            "certutil $verb (mock)"
        }
        $script:Plan = InModuleScope NSP.PKI { Get-CAPublicationUrlPlan -CrlFqdn 'crl.example.test' -OcspFqdn 'ocsp.example.test' }
    }
    AfterEach { InModuleScope NSP.PKI { Set-CADryRun -Enabled $true } }

    It 'does nothing in a dry run' {
        InModuleScope NSP.PKI -Parameters @{ Plan = $Plan } { Set-CAPublicationUrls -Plan $Plan }
        $Calls.Count | Should -Be 0
    }

    It 'sets both URL lists, restarts the service, then republishes, in that order' {
        InModuleScope NSP.PKI -Parameters @{ Plan = $Plan } { Set-CADryRun -Enabled $false; Set-CAPublicationUrls -Plan $Plan }
        $Calls.Count | Should -Be 5
        $Calls[0] | Should -BeLike '-setreg CA\CRLPublicationURLs *'
        $Calls[1] | Should -BeLike '-setreg CA\CACertPublicationURLs *'
        $Calls[2] | Should -Be 'restart CertSvc'
        $Calls[3] | Should -Be '-ping'
        $Calls[4] | Should -Be '-crl'
    }

    It 'expands the Windows folder but leaves the CA''s own tokens alone' {
        InModuleScope NSP.PKI -Parameters @{ Plan = $Plan } { Set-CADryRun -Enabled $false; Set-CAPublicationUrls -Plan $Plan -SkipServiceRestart -SkipCrlRepublish }
        $Calls.Count | Should -Be 2
        $Calls[0] | Should -Not -Match '%windir%'
        $Calls[0] | Should -Match ([regex]::Escape((Join-Path $env:windir 'system32\CertSrv\CertEnroll\%3%8%9.crl')))
        $Calls[0] | Should -Match ([regex]::Escape('6:http://crl.example.test/CertEnroll/%3%8%9.crl'))
        $Calls[0] | Should -Match ([regex]::Escape('CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10'))
        $Calls[1] | Should -Match ([regex]::Escape('2:http://crl.example.test/CertEnroll/%1_%3%4.crt'))
        $Calls[1] | Should -Match ([regex]::Escape('32:http://ocsp.example.test/ocsp'))
    }

    It 'honours the skip switches' {
        InModuleScope NSP.PKI -Parameters @{ Plan = $Plan } { Set-CADryRun -Enabled $false; Set-CAPublicationUrls -Plan $Plan -SkipServiceRestart }
        @($Calls | Where-Object { $_ -like 'restart*' -or $_ -eq '-ping' }).Count | Should -Be 0
        $Calls[-1] | Should -Be '-crl'
        $Calls.Clear()
        InModuleScope NSP.PKI -Parameters @{ Plan = $Plan } { Set-CAPublicationUrls -Plan $Plan -SkipCrlRepublish }
        @($Calls | Where-Object { $_ -eq '-crl' }).Count | Should -Be 0
        $Calls[-1] | Should -Be '-ping'
    }

    It 'stops at the first failed registry change and does not restart the service' {
        $ExitCodes.setreg = 5
        {
            InModuleScope NSP.PKI -Parameters @{ Plan = $Plan } { Set-CADryRun -Enabled $false; Set-CAPublicationUrls -Plan $Plan }
        } | Should -Throw '*CRLPublicationURLs failed (exit 5)*'
        $Calls.Count | Should -Be 1
    }

    It 'throws when the CA does not answer after the restart, and does not republish' {
        $ExitCodes.ping = 1
        {
            InModuleScope NSP.PKI -Parameters @{ Plan = $Plan } { Set-CADryRun -Enabled $false; Set-CAPublicationUrls -Plan $Plan }
        } | Should -Throw '*not answering RPC*'
        @($Calls | Where-Object { $_ -eq '-ping' }).Count | Should -Be 20
        @($Calls | Where-Object { $_ -eq '-crl' }).Count | Should -Be 0
    }

    It 'does not throw when only the republish fails' {
        $ExitCodes.crl = 1
        { InModuleScope NSP.PKI -Parameters @{ Plan = $Plan } { Set-CADryRun -Enabled $false; Set-CAPublicationUrls -Plan $Plan } } | Should -Not -Throw
        @($Calls | Where-Object { $_ -eq '-crl' }).Count | Should -Be 1
    }
}
