<#
    Pester 5. The CA key report (Get-NSPPkiCAKeyReport and Private\CAKeyReport.ps1).

    The three certificates below are throwaway self-signed test certificates made with OpenSSL; their
    private keys were discarded when they were made. The expected fingerprints were computed by
    OpenSSL, not by this module:
        openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
    so a mistake in the hand-built encoding here cannot agree with them by accident.

    No test reads this machine's registry or certificate store: the two local readers are mocked.
#>

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.PKI.psd1') -Force -ErrorAction Stop

    $script:Vectors = @{
        Rsa   = @{
            Sha256 = '767534de889c2ec69fdf225d6d2b81f351039ebfddf0dfa4cc63b258e12d04c8'; Bits = 2048
            Der    = 'MIIDHTCCAgWgAwIBAgIUWZZLC3g3ax06sHKQD94ONfybMQEwDQYJKoZIhvcNAQELBQAwHjEcMBoGA1UEAwwTRVhBTVBMRS1SU0EtVEVTVC1DQTAeFw0yNjExMTQxNTQ3MzFaFw0zNjExMTExNTQ3MzFaMB4xHDAaBgNVBAMME0VYQU1QTEUtUlNBLVRFU1QtQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFpdBq45HyrOp/3wPU/XX8GdaHL0n32XeAM/UmfJFeZ0ISzR1bfMKGp7C2fhMLwr3IBGDYSWHre2w8GoGACPMFXawAp2h0KsUi66nGH7sKtSXzPM7yzuWlLG8ZsTEZt7Z1yNoNfnW8DKM6QKiPN3jJxhtoS0k2/SmeCfI0/1nmvOZ8TSkKkLYqLM/UQVysCPvEeovuWTYH/Rv8T+VWHIOIjUieR+1b/fC8v1XgNVqJkE7hSDYRs7h77i1iuAs88LkaR4t9In3wk0vIWpVeBb+GLn1YIybhZOZNG/M7Gobwf3B9pTwZ77vlWLZ9Ihlg/a+U70CnAxAIBjaZsTVX7COhAgMBAAGjUzBRMB0GA1UdDgQWBBTD2drHaHxOcJrjut87WnRtuhYqqzAfBgNVHSMEGDAWgBTD2drHaHxOcJrjut87WnRtuhYqqzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCD4P/utgRBC35fT3hvNIFu0Kwxw3g341YzNmMRYNnVosTy3i8sFQdO4lXL3Au6FqvA/EfCT1RL6U0MrQ9cFMGMdWO4SI7mgU1uyiW2czTFruovqzErY4pJPYSP3u/WrgZwM7vYX9SinZKQOJMKIV6APq7EYkDWTECEIEeyJsqbbP+kirGoxfl9Nze0gNzVCrGzu0ThBkqKljJ9yofNxTWJMciGR0tA2wdgJTYnPyUYOji+woU1byRWc2xe9PTOQWBBN16yDfMmaFjARwiZ7DbrmzBuwZumlaDzVOMF8cTd69CjgqFbF9WcubkVz67HQdg12xM3l2ivXmb0OrKhZjKB'
        }
        Ec256 = @{
            Sha256 = '76a280fdde96dc4e74e25bf61b35c0c6c3cc40229ba3cf7b96526e8386b9e0c4'; Bits = 256
            Der    = 'MIIBjjCCATWgAwIBAgIUJatTMMA6WEEBoM/B9Wynf9PFYEEwCgYIKoZIzj0EAwIwHTEbMBkGA1UEAwwSRVhBTVBMRS1FQy1URVNULUNBMB4XDTI2MTExNDE1NDczMVoXDTM2MTExMTE1NDczMVowHTEbMBkGA1UEAwwSRVhBTVBMRS1FQy1URVNULUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU1aGJR4EQuraSFpk3uDgpGFrfj5DazrXxeCCZdZcVY1QS4q/6lO0t7qYCBLYK8QDCaxi+AgrJJTy6B0bZwfklqNTMFEwHQYDVR0OBBYEFFPlD5NjAMey0atks3SQRUYatGMcMB8GA1UdIwQYMBaAFFPlD5NjAMey0atks3SQRUYatGMcMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgXAqd+Npd+MXvO/VD//g2lz7IxtuTKg/fZmqMjNT1zJACIB2TsJ4N+EOb3vJS822Xr6lVdbSP1iDpWL5s3+Y66cCP'
        }
        Ec384 = @{
            Sha256 = '3239606f12f31bbba4346e42a4d024653d9e6338ad0100386591543737efcbdd'; Bits = 384
            Der    = 'MIIB0zCCAVigAwIBAgIUSzpP8BRzx8tFkAYl7EPBl1bnS6IwCgYIKoZIzj0EAwIwIDEeMBwGA1UEAwwVRVhBTVBMRS1FQzM4NC1URVNULUNBMB4XDTI2MTExNDE1NDczMVoXDTM2MTExMTE1NDczMVowIDEeMBwGA1UEAwwVRVhBTVBMRS1FQzM4NC1URVNULUNBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8u4V0J8TSl86uVtwNM/FIXS8ADbQyfLV7Kil/0RyJwB8AdBYGu78olpxdpQP5sg+4js//aVFJcJVLCdMFkK0D7HUP4dn9cJTq95mPwIYXukqYyFDHz0X555GSiqo6Z3Zo1MwUTAdBgNVHQ4EFgQUC5/W+sOXvuKMXu6iiq+1wV/gDTAwHwYDVR0jBBgwFoAUC5/W+sOXvuKMXu6iiq+1wV/gDTAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNpADBmAjEA3bFH7TKl8kTfmIlEe+v8oSVROlXaPA3PVNlO6lK6WUIngKM9uY0/A15SDrRzXaBcAjEA5MNF/dHDr+1t6bKdcF+AP+OzVlcqUSlB8kZfWVOFr3qql/etb/BoRUEVC2hqusY0'
        }
    }
    function Get-TestCertificate([string]$Name) {
        New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, [Convert]::FromBase64String($script:Vectors[$Name].Der))
    }
    $script:RsaCert = Get-TestCertificate 'Rsa'
    $script:LocalConfiguration = [pscustomobject]@{
        CACommonName = 'EXAMPLE-RSA-TEST-CA'; Thumbprint = $script:RsaCert.Thumbprint
        ProviderName = 'Microsoft Software Key Storage Provider'; HashAlgorithm = 'SHA256'; PublicKeyAlgorithm = 'RSA'
    }
}

AfterAll { Remove-Module NSP.PKI -Force -ErrorAction SilentlyContinue }

Describe 'DER encoding helpers' {
    It 'encodes a length of <Length> as <Expected>' -ForEach @(
        @{ Length = 0; Expected = '0400' }
        @{ Length = 127; Expected = '047F' }
        @{ Length = 128; Expected = '048180' }
        @{ Length = 255; Expected = '0481FF' }
        @{ Length = 256; Expected = '04820100' }
        @{ Length = 65536; Expected = '0483010000' }
    ) {
        InModuleScope NSP.PKI -Parameters @{ Length = $Length; Expected = $Expected } {
            $der = ConvertTo-CADerElement -Tag 0x04 -Content (New-Object byte[] $Length)
            $der.Length | Should -Be ($Expected.Length / 2 + $Length)
            (-join ($der[0..($Expected.Length / 2 - 1)] | ForEach-Object { $_.ToString('X2') })) | Should -Be $Expected
        }
    }

    It 'encodes object identifier <Oid> as <Expected>' -ForEach @(
        @{ Oid = '1.2.840.113549.1.1.1'; Expected = '06092A864886F70D010101' }
        @{ Oid = '1.2.840.10045.2.1'; Expected = '06072A8648CE3D0201' }
        @{ Oid = '1.3.132.0.34'; Expected = '06052B81040022' }
        @{ Oid = '2.5.29.19'; Expected = '0603551D13' }
        @{ Oid = '2.999.3'; Expected = '0603883703' }
        @{ Oid = '0.0'; Expected = '060100' }
    ) {
        InModuleScope NSP.PKI -Parameters @{ Oid = $Oid; Expected = $Expected } {
            $der = ConvertTo-CADerObjectIdentifier -Value $Oid
            (-join ($der | ForEach-Object { $_.ToString('X2') })) | Should -Be $Expected
        }
    }

    It 'refuses <Value> as an object identifier' -ForEach @(
        @{ Value = '1' }, @{ Value = '3.1' }, @{ Value = '1.40.1' }, @{ Value = '1.2.' }, @{ Value = '1.02.3' }, @{ Value = 'RSA' }, @{ Value = '1.2 .3' }
    ) {
        InModuleScope NSP.PKI -Parameters @{ Value = $Value } {
            { ConvertTo-CADerObjectIdentifier -Value $Value } | Should -Throw '*Not an object identifier*'
        }
    }
}

Describe 'Public key fingerprint' {
    It 'matches the fingerprint OpenSSL computed for the <Name> certificate' -ForEach @(
        @{ Name = 'Rsa' }, @{ Name = 'Ec256' }, @{ Name = 'Ec384' }
    ) {
        $report = Get-NSPPkiCAKeyReport -Certificate (Get-TestCertificate $Name)
        $report.Status | Should -Be 'Ok'
        $report.PublicKeySha256 | Should -BeExactly $Vectors[$Name].Sha256
        $report.PublicKeyBits | Should -Be $Vectors[$Name].Bits
    }

    It 'builds the same bytes as the .NET export for the <Name> certificate' -Skip:($PSVersionTable.PSVersion.Major -lt 7) -ForEach @(
        @{ Name = 'Rsa' }, @{ Name = 'Ec256' }, @{ Name = 'Ec384' }
    ) {
        $certificate = Get-TestCertificate $Name
        $expected = [Convert]::ToBase64String($certificate.PublicKey.ExportSubjectPublicKeyInfo())
        InModuleScope NSP.PKI -Parameters @{ Certificate = $certificate; Expected = $expected } {
            [Convert]::ToBase64String((Get-CAPublicKeyInfoDer -Certificate $Certificate)) | Should -BeExactly $Expected
        }
    }

    It 'gives different certificates on different keys different fingerprints' {
        $all = @('Rsa', 'Ec256', 'Ec384' | ForEach-Object { (Get-NSPPkiCAKeyReport -Certificate (Get-TestCertificate $_)).PublicKeySha256 })
        @($all | Sort-Object -Unique).Count | Should -Be 3
    }

    It 'reads a certificate file, binary or Base64' {
        $binary = Join-Path $TestDrive 'ca.cer'
        [System.IO.File]::WriteAllBytes($binary, $RsaCert.RawData)
        $text = Join-Path $TestDrive 'ca-b64.cer'
        Set-Content -LiteralPath $text -Encoding ASCII -Value @('-----BEGIN CERTIFICATE-----', $Vectors.Rsa.Der, '-----END CERTIFICATE-----')
        (Get-NSPPkiCAKeyReport -CertificatePath $binary).PublicKeySha256 | Should -BeExactly $Vectors.Rsa.Sha256
        (Get-NSPPkiCAKeyReport -CertificatePath $text).PublicKeySha256 | Should -BeExactly $Vectors.Rsa.Sha256
    }

    It 'throws for a certificate file that does not exist' {
        { Get-NSPPkiCAKeyReport -CertificatePath (Join-Path $TestDrive 'missing.cer') } | Should -Throw
    }
}

Describe 'Report on a certificate' {
    It 'fills the certificate fields and leaves the CA configuration fields empty' {
        $report = Get-NSPPkiCAKeyReport -Certificate $RsaCert
        $report.Source | Should -Be 'Certificate'
        $report.Subject | Should -Be 'CN=EXAMPLE-RSA-TEST-CA'
        $report.Thumbprint | Should -Be $RsaCert.Thumbprint
        $report.PublicKeyAlgorithm | Should -Not -BeNullOrEmpty
        $report.HasPrivateKeyReference | Should -BeFalse
        $report.CACommonName | Should -BeNullOrEmpty
        $report.ProviderName | Should -BeNullOrEmpty
        $report.ProviderClass | Should -Be 'Unknown'
        $report.PublicKeyMatchesExpected | Should -BeNullOrEmpty
    }

    It 'never reports whether the key can be exported' {
        $report = Get-NSPPkiCAKeyReport -Certificate $RsaCert
        @($report.PSObject.Properties.Name) | Should -Contain 'KeyExportable'
        $report.KeyExportable | Should -BeNullOrEmpty
    }

    It 'says the key matches the recorded fingerprint, whatever its case or separators' {
        $spaced = ($Vectors.Rsa.Sha256.ToUpperInvariant() -replace '(..)(?=.)', '$1:')
        (Get-NSPPkiCAKeyReport -Certificate $RsaCert -ExpectedPublicKeySha256 $Vectors.Rsa.Sha256).PublicKeyMatchesExpected | Should -BeTrue
        $report = Get-NSPPkiCAKeyReport -Certificate $RsaCert -ExpectedPublicKeySha256 $spaced
        $report.PublicKeyMatchesExpected | Should -BeTrue
        $report.ExpectedPublicKeySha256 | Should -BeExactly $Vectors.Rsa.Sha256
    }

    It 'says the key does not match when the recorded fingerprint is another key''s' {
        $report = Get-NSPPkiCAKeyReport -Certificate $RsaCert -ExpectedPublicKeySha256 $Vectors.Ec256.Sha256
        $report.Status | Should -Be 'Ok'
        $report.PublicKeyMatchesExpected | Should -BeFalse
    }

    It 'refuses <Value> as a recorded fingerprint' -ForEach @(
        @{ Value = 'abc' }, @{ Value = ('g' * 64) }, @{ Value = ('a' * 63) }, @{ Value = ('a' * 65) }
    ) {
        { Get-NSPPkiCAKeyReport -Certificate $RsaCert -ExpectedPublicKeySha256 $Value } | Should -Throw '*64 hexadecimal*'
        Mock -ModuleName NSP.PKI Get-CALocalKeyConfiguration { throw 'must not be read' }
        { Get-NSPPkiCAKeyReport -ExpectedPublicKeySha256 $Value } | Should -Throw '*64 hexadecimal*'
        Should -Invoke -ModuleName NSP.PKI Get-CALocalKeyConfiguration -Times 0 -Exactly
    }
}

Describe 'Report on the local CA' {
    It 'returns NoLocalCA, without throwing, on a machine with no CA' {
        Mock -ModuleName NSP.PKI Get-CALocalKeyConfiguration { $null }
        Mock -ModuleName NSP.PKI Get-CALocalCertificate { throw 'must not be read' }
        $report = Get-NSPPkiCAKeyReport -ExpectedPublicKeySha256 $Vectors.Rsa.Sha256
        $report.Status | Should -Be 'NoLocalCA'
        $report.Source | Should -Be 'LocalCA'
        $report.PublicKeySha256 | Should -BeNullOrEmpty
        $report.PublicKeyMatchesExpected | Should -BeNullOrEmpty
        $report.Detail | Should -Not -BeNullOrEmpty
        Should -Invoke -ModuleName NSP.PKI Get-CALocalCertificate -Times 0 -Exactly
    }

    It 'returns CACertificateNotFound when the configured certificate is not in the store' {
        Mock -ModuleName NSP.PKI Get-CALocalKeyConfiguration { $script:LocalConfiguration }
        Mock -ModuleName NSP.PKI Get-CALocalCertificate { $null }
        $report = Get-NSPPkiCAKeyReport
        $report.Status | Should -Be 'CACertificateNotFound'
        $report.CACommonName | Should -Be 'EXAMPLE-RSA-TEST-CA'
        $report.ProviderClass | Should -Be 'MicrosoftSoftware'
        $report.PublicKeySha256 | Should -BeNullOrEmpty
    }

    It 'returns CACertificateNotFound when the configuration names no certificate' {
        Mock -ModuleName NSP.PKI Get-CALocalKeyConfiguration { [pscustomobject]@{ CACommonName = 'EXAMPLE-RSA-TEST-CA'; Thumbprint = $null; ProviderName = $null; HashAlgorithm = $null; PublicKeyAlgorithm = $null } }
        Mock -ModuleName NSP.PKI Get-CALocalCertificate { throw 'must not be read' }
        $report = Get-NSPPkiCAKeyReport
        $report.Status | Should -Be 'CACertificateNotFound'
        $report.ProviderClass | Should -Be 'Unknown'
        Should -Invoke -ModuleName NSP.PKI Get-CALocalCertificate -Times 0 -Exactly
    }

    It 'returns Ok with the key fingerprint and the configured provider' {
        Mock -ModuleName NSP.PKI Get-CALocalKeyConfiguration { $script:LocalConfiguration }
        Mock -ModuleName NSP.PKI Get-CALocalCertificate { $script:RsaCert }
        $report = Get-NSPPkiCAKeyReport -ExpectedPublicKeySha256 $Vectors.Rsa.Sha256
        $report.Status | Should -Be 'Ok'
        $report.Source | Should -Be 'LocalCA'
        $report.CACommonName | Should -Be 'EXAMPLE-RSA-TEST-CA'
        $report.PublicKeySha256 | Should -BeExactly $Vectors.Rsa.Sha256
        $report.PublicKeyBits | Should -Be 2048
        $report.PublicKeyMatchesExpected | Should -BeTrue
        $report.ProviderName | Should -Be 'Microsoft Software Key Storage Provider'
        $report.ProviderClass | Should -Be 'MicrosoftSoftware'
        $report.ConfiguredHashAlgorithm | Should -Be 'SHA256'
        Should -Invoke -ModuleName NSP.PKI Get-CALocalCertificate -Times 1 -Exactly -ParameterFilter { $Thumbprint -eq $script:RsaCert.Thumbprint }
    }

    It 'reports a replaced key as a mismatch even when name, size and provider are unchanged' {
        # The case the report exists for: same CA name, same provider label, a different key underneath.
        Mock -ModuleName NSP.PKI Get-CALocalKeyConfiguration { $script:LocalConfiguration }
        Mock -ModuleName NSP.PKI Get-CALocalCertificate { $script:RsaCert }
        $report = Get-NSPPkiCAKeyReport -ExpectedPublicKeySha256 ('0' * 64)
        $report.Status | Should -Be 'Ok'
        $report.PublicKeyMatchesExpected | Should -BeFalse
    }

    It 'returns CannotRead, without throwing, when a read fails' {
        Mock -ModuleName NSP.PKI Get-CALocalKeyConfiguration { throw 'Requested registry access is not allowed.' }
        $report = Get-NSPPkiCAKeyReport
        $report.Status | Should -Be 'CannotRead'
        $report.Detail | Should -BeLike '*not allowed*'
        $report.PublicKeySha256 | Should -BeNullOrEmpty
    }

    It 'returns CannotRead and keeps the configuration when the certificate store read fails' {
        Mock -ModuleName NSP.PKI Get-CALocalKeyConfiguration { $script:LocalConfiguration }
        Mock -ModuleName NSP.PKI Get-CALocalCertificate { throw 'store unavailable' }
        $report = Get-NSPPkiCAKeyReport
        $report.Status | Should -Be 'CannotRead'
        $report.CACommonName | Should -Be 'EXAMPLE-RSA-TEST-CA'
        $report.Detail | Should -BeLike '*store unavailable*'
    }
}

Describe 'Local CA configuration reader' {
    It 'returns nothing when Certificate Services has no configuration' {
        InModuleScope NSP.PKI {
            Mock Test-Path { $false }
            Mock Get-ItemProperty { throw 'must not be read' }
            Get-CALocalKeyConfiguration | Should -BeNullOrEmpty
        }
    }

    It 'returns nothing when no CA is marked active' {
        InModuleScope NSP.PKI {
            Mock Test-Path { $true }
            Mock Get-ItemProperty { [pscustomobject]@{ Active = '' } }
            Get-CALocalKeyConfiguration | Should -BeNullOrEmpty
        }
    }

    It 'reads the name, the newest certificate thumbprint and the provider' {
        InModuleScope NSP.PKI {
            Mock Test-Path { $true }
            Mock Get-ItemProperty { [pscustomobject]@{ Active = 'EXAMPLE-RSA-TEST-CA' } } -ParameterFilter { $LiteralPath -like '*\Configuration' }
            Mock Get-ItemProperty { [pscustomobject]@{ CACertHash = @('11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11', 'aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd', '') } } -ParameterFilter { $LiteralPath -like '*\EXAMPLE-RSA-TEST-CA' }
            Mock Get-ItemProperty { [pscustomobject]@{ Provider = 'Example Hardware Provider'; CNGHashAlgorithm = 'SHA384'; CNGPublicKeyAlgorithm = 'RSA' } } -ParameterFilter { $LiteralPath -like '*\CSP' }
            $configuration = Get-CALocalKeyConfiguration
            $configuration.CACommonName | Should -Be 'EXAMPLE-RSA-TEST-CA'
            $configuration.Thumbprint | Should -BeExactly 'AABBCCDDEEFF00112233445566778899AABBCCDD'
            $configuration.ProviderName | Should -Be 'Example Hardware Provider'
            $configuration.HashAlgorithm | Should -Be 'SHA384'
            $configuration.PublicKeyAlgorithm | Should -Be 'RSA'
        }
    }
}

Describe 'Provider class' {
    It 'classes <Name> as <Expected>' -ForEach @(
        @{ Name = 'Microsoft Software Key Storage Provider'; Expected = 'MicrosoftSoftware' }
        @{ Name = 'RSA#Microsoft Software Key Storage Provider'; Expected = 'MicrosoftSoftware' }
        @{ Name = 'ECDSA_P256#Microsoft Software Key Storage Provider'; Expected = 'MicrosoftSoftware' }
        @{ Name = 'Microsoft Strong Cryptographic Provider'; Expected = 'MicrosoftSoftware' }
        @{ Name = 'Example Hardware Provider'; Expected = 'Other' }
        @{ Name = 'Microsoft Platform Crypto Provider'; Expected = 'Other' }
        @{ Name = 'Microsoft Software Key Storage Provider (copy)'; Expected = 'Other' }
        @{ Name = ''; Expected = 'Unknown' }
        @{ Name = '   '; Expected = 'Unknown' }
    ) {
        InModuleScope NSP.PKI -Parameters @{ Name = $Name; Expected = $Expected } {
            Get-CAProviderClass -ProviderName $Name | Should -Be $Expected
        }
    }
}

Describe 'The key report stays read-only' {
    It '<File> has no call that opens, exports or changes a key, the registry or the CA' -ForEach @(
        @{ File = 'Private\CAKeyReport.ps1' }, @{ File = 'Public\Get-NSPPkiCAKeyReport.ps1' }
    ) {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) $File
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
        $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $changing = @($commands | Where-Object { $_ -match '^(Set|New|Remove|Clear|Import|Export|Install|Uninstall|Restart|Stop|Start|Add|Invoke|Backup|Restore|Rename|Move|Copy)-' -and $_ -notin 'New-Object', 'New-CAKeyReport' })
        $changing | Should -BeNullOrEmpty
        @($commands | Where-Object { $_ -match '(?i)certutil|certreq|\.exe$' }) | Should -BeNullOrEmpty
        $members = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.MemberExpressionAst] }, $true) | ForEach-Object { [string]$_.Member })
        @($members | Where-Object { $_ -match '^(PrivateKey|Export|ExportPkcs8PrivateKey|ExportParameters|GetRSAPrivateKey|GetECDsaPrivateKey|CopyWithPrivateKey|Import|SetValue|DeleteValue)$' }) | Should -BeNullOrEmpty
    }
}
