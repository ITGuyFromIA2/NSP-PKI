<#
    Pester 5. The NSP.PKI module glue (the CA engine itself is covered by Tests\Legacy). Sibling
    checkouts are loaded first; NSP_TOOLKIT_ROOT keeps the work folder in $TestDrive.
#>

BeforeAll {
    $toolkits = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path (Split-Path -Parent $toolkits) 'NSP-Bootstrap\NSP.Bootstrap.psd1') -Force -Global -ErrorAction Stop
    foreach ($m in 'NSP-Console\NSP.Console.psd1', 'NSP-Toolkit\NSP.Toolkit.psd1', 'NSP-ClientScripts\NSP.ClientScripts.psd1') {
        Import-Module (Join-Path $toolkits $m) -Force -Global -ErrorAction Stop
    }
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.PKI.psd1') -Force -ErrorAction Stop

    $script:Client = [pscustomobject]@{
        Company_Name = 'Example-Co'; AuthMethod = 'Certificate'; Cert_CertificateName = 'EXAMPLE-FGT'; Cert_PeerName = 'P_IKEv2_Example'
        CA_CommonName = 'EXAMPLE-ISSUING-CA'; CA_TemplateAuto = 'IKEv2VPN-Example'; CA_SubjectStampMode = 'TameMyCerts'
        RadiusGroupPairs = @([pscustomobject]@{ Label = 'Staff'; UserGroupValue = 'vpn_staff' }); IPSecTunnelName = 'Example-IKEv2'
    }

    # A throwaway self-signed PFX (no certificate store involved).
    function New-TestPfx([string]$ExportKey) {
        $rsa = [Security.Cryptography.RSA]::Create(2048)
        $req = New-Object Security.Cryptography.X509Certificates.CertificateRequest('CN=EXAMPLE-FGT', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $cert = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(30))
        $bytes = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $ExportKey)
        [pscustomobject]@{ Bytes = $bytes; Thumbprint = $cert.Thumbprint }
    }
}

AfterAll {
    Remove-Item Env:\NSP_TOOLKIT_ROOT -ErrorAction SilentlyContinue
    Remove-Module NSP.PKI -Force -ErrorAction SilentlyContinue
}

Describe 'NSP.PKI' {
    BeforeEach {
        $env:NSP_TOOLKIT_ROOT = Join-Path $TestDrive ('tk_' + [guid]::NewGuid().ToString('N'))
        Mock -ModuleName NSP.Toolkit Write-Host { }
        Mock -ModuleName NSP.PKI Write-Host { }
    }

    Context 'ConvertTo-NSPPkiAnswers' {
        It 'carries the same fields the Orchestrator staged into the zip-era launcher' {
            $a = ConvertTo-NSPPkiAnswers -ClientAnswers $Client
            $a.Company_Name | Should -Be 'Example-Co'
            @($a.PSObject.Properties.Name) | Should -Not -Contain 'CompanyName'
            $a.Cert_PeerName | Should -Be 'P_IKEv2_Example'
            $a.CA_CommonName | Should -Be 'EXAMPLE-ISSUING-CA'
            $a.CA_SubjectStampMode | Should -Be 'TameMyCerts'
            @($a.RadiusGroupPairs).Count | Should -Be 1
            @($a.PSObject.Properties.Name) | Should -Not -Contain 'IPSecTunnelName'
        }
        It 'returns nothing for a client without certificate auth' {
            $p = $Client.PSObject.Copy(); $p.AuthMethod = 'PSK'
            ConvertTo-NSPPkiAnswers -ClientAnswers $p | Should -BeNullOrEmpty
        }
        It 'reads a ClientAnswers file' {
            $f = Join-Path $TestDrive 'EXAMPLE.json'; $Client | ConvertTo-Json -Depth 5 | Set-Content $f
            (ConvertTo-NSPPkiAnswers -ClientAnswers $f).CA_TemplateAuto | Should -Be 'IKEv2VPN-Example'
        }
    }

    Context 'Launcher and seed answers' {
        It 'writes a launcher carrying the answers' {
            $p = Join-Path $TestDrive 'PKI-Manager.ps1'
            New-NSPPkiShim -ClientAnswers $Client -Path $p -GeneratedBy 'test' -Force | Should -BeOfType [IO.FileInfo]
            $text = Get-Content -LiteralPath $p -Raw
            $parseErrors = $null
            [Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$parseErrors) | Out-Null
            $parseErrors | Should -BeNullOrEmpty
            $text | Should -Match "EntryFunction\s+= 'Start-NSPPkiManager'"
            $text | Should -Match '"CA_CommonName":\s+"EXAMPLE-ISSUING-CA"'
            $text | Should -Match '"Company_Name":\s+"Example-Co"'
            $text | Should -Match 'Example-Co'
        }
        It 'gives the engine Company_Name from answers staged with the old CompanyName' {
            $old = [pscustomobject]@{ CompanyName = 'Example-Co'; CA_CommonName = 'EXAMPLE-ISSUING-CA' }
            (InModuleScope NSP.PKI -Parameters @{ A = $old } { param($A) Repair-PKIAnswerField -CAAnswers $A }).Company_Name | Should -Be 'Example-Co'
            $both = [pscustomobject]@{ CompanyName = 'Old'; Company_Name = 'Current' }
            (InModuleScope NSP.PKI -Parameters @{ A = $both } { param($A) Repair-PKIAnswerField -CAAnswers $A }).Company_Name | Should -Be 'Current'
            InModuleScope NSP.PKI { Repair-PKIAnswerField -CAAnswers $null } | Should -BeNullOrEmpty
        }
        It 'refuses a client without certificate auth' {
            $p = $Client.PSObject.Copy(); $p.AuthMethod = 'PSK'
            { New-NSPPkiShim -ClientAnswers $p -Path (Join-Path $TestDrive 'x.ps1') } | Should -Throw '*certificate authentication*'
        }
        It 'merges seed answers with -SeedOnly into the PKI work folder' {
            $json = ConvertTo-NSPPkiAnswers -ClientAnswers $Client | ConvertTo-Json -Depth 5
            Start-NSPPkiManager -SeedAnswersJson $json -SeedOnly
            (Get-NSPToolAnswers -Tool PKI).CA_CommonName | Should -Be 'EXAMPLE-ISSUING-CA'
        }
        It 'expects the answers'' templates in the status header, else the standard set' {
            InModuleScope NSP.PKI { (Get-PKIExpectedTemplate -CAAnswers $null) -join ',' } | Should -Be 'IKEv2VPN-InternalUsers,IKEv2VPN-InternalUsers-MANUAL,FortiGate'
            InModuleScope NSP.PKI { (Get-PKIExpectedTemplate -CAAnswers ([pscustomobject]@{ CA_TemplateAuto = 'A'; CA_TemplateFortiGate = 'F' })) -join ',' } | Should -Be 'A,F'
        }
        It 'saves a CA configuration name into Answers.json, keeping the other answers' {
            $file = Join-Path (Get-NSPToolWorkPath -Tool PKI -Kind Answers -Create) 'Answers.json'
            '{"CompanyName":"Example-Co"}' | Set-Content $file
            InModuleScope NSP.PKI -Parameters @{ File = $file } { param($File) Set-PKIToolAnswerField -Path $File -Field 'PKICAConfigName' -Value 'ca01\EXAMPLE-ISSUING-CA' }
            $a = Get-NSPToolAnswers -Tool PKI
            $a.PKICAConfigName | Should -Be 'ca01\EXAMPLE-ISSUING-CA'
            $a.CompanyName | Should -Be 'Example-Co'
        }
    }

    Context 'Hand-back (menu 13)' {
        BeforeEach {
            $script:Pfx = New-TestPfx -ExportKey 'not-a-real-password'
            $script:Response = [pscustomobject][ordered]@{
                Schema = 4; GeneratedUtc = '2026-01-15T10:00:00Z'; CAManagerVersion = '0.1.0'; Company = 'Example-Co'
                CACommonName = 'EXAMPLE-ISSUING-CA'; FortiGatePfxBase64 = [Convert]::ToBase64String($Pfx.Bytes)
                FortiGatePfxPassword = 'not-a-real-password'; FortiGatePfxFile = 'ExampleCo_FortiGate.pfx'; FortiGateCertThumbprint = $Pfx.Thumbprint
            }
            InModuleScope NSP.PKI { Set-CADryRun -Enabled $false }
        }
        AfterEach { InModuleScope NSP.PKI { Set-CADryRun -Enabled $true } }

        It 'writes a PKI Response hand-off the Orchestrator Inbox can read, PFX still embedded' {
            $out = Join-Path $TestDrive ('h_' + [guid]::NewGuid().ToString('N'))
            $w = InModuleScope NSP.PKI -Parameters @{ R = $Response; O = $out } { param($R, $O) Write-CAHandoffFiles -Response $R -OutputDir $O }
            Split-Path -Leaf $w.JsonPath | Should -Be 'Example-Co_PKI_Response.json'
            Test-Path -LiteralPath $w.JsonPath | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $out 'ExampleCo_CAResponse.json') | Should -BeFalse
            $h = Import-NSPHandoff -Path $w.JsonPath -Tool PKI -Kind Response
            $h.HashValid | Should -BeTrue
            $h.PayloadSchema | Should -Be 4
            $h.Payload.FortiGatePfxBase64 | Should -Be $Response.FortiGatePfxBase64
            $h.Payload.CACommonName | Should -Be 'EXAMPLE-ISSUING-CA'
        }
        It 'writes nothing in DRY RUN' {
            InModuleScope NSP.PKI { Set-CADryRun -Enabled $true }
            $out = Join-Path $TestDrive ('d_' + [guid]::NewGuid().ToString('N'))
            $null = InModuleScope NSP.PKI -Parameters @{ R = $Response; O = $out } { param($R, $O) Write-CAHandoffFiles -Response $R -OutputDir $O }
            Test-Path -LiteralPath $out | Should -BeFalse
        }
        It 'offers the FortiGate cert from the last hand-off for reuse (re-running menu 13)' {
            $out = Join-Path $TestDrive ('r_' + [guid]::NewGuid().ToString('N'))
            $null = InModuleScope NSP.PKI -Parameters @{ R = $Response; O = $out } { param($R, $O) Write-CAHandoffFiles -Response $R -OutputDir $O }
            $id = InModuleScope NSP.PKI -Parameters @{ O = $out } { param($O) Get-CAHandoffIdentity -OutputDir $O -CompanyStem 'ExampleCo' }
            $id.Kind | Should -Be 'PFX'
            $id.Thumbprint | Should -Be $Pfx.Thumbprint
            $id.Password | Should -Be 'not-a-real-password'
            Test-Path -LiteralPath $id.PfxPath | Should -BeTrue
        }
        It 'still reuses the cert from a zip-era _CAResponse.json' {
            $out = Join-Path $TestDrive ('l_' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $out | Out-Null
            $Response | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $out 'ExampleCo_CAResponse.json')
            $id = InModuleScope NSP.PKI -Parameters @{ O = $out } { param($O) Get-CAHandoffIdentity -OutputDir $O -CompanyStem 'ExampleCo' }
            $id.Thumbprint | Should -Be $Pfx.Thumbprint
        }
        It 'ignores another company''s hand-off in the same folder' {
            $out = Join-Path $TestDrive ('o_' + [guid]::NewGuid().ToString('N'))
            $null = InModuleScope NSP.PKI -Parameters @{ R = $Response; O = $out } { param($R, $O) Write-CAHandoffFiles -Response $R -OutputDir $O }
            InModuleScope NSP.PKI -Parameters @{ O = $out } { param($O) Get-CAHandoffIdentity -OutputDir $O -CompanyStem 'OtherCo' } | Should -BeNullOrEmpty
        }
    }

    Context 'Relaunch from the module' {
        It 'starts Start-NSPPkiManager elevated and signals the dashboard to return instead of exiting the host' {
            Mock -ModuleName NSP.PKI Start-Process { }
        Mock -ModuleName NSP.PKI Get-NSPDesktopUserSid { 'S-1-5-21-1-2-3-1001' }
        Mock -ModuleName NSP.PKI Grant-NSPFolderRead { }
            $err = $null
            try { InModuleScope NSP.PKI { Invoke-CAManagerRelaunch -ScriptPath 'C:\Modules\NSP.PKI\NSP.PKI.psd1' -CAConfigName "ca01\Example's CA" } }
            catch { $err = $_.Exception }
            $err | Should -BeOfType [System.OperationCanceledException]
            $err.Message | Should -Be 'NSP.PKI:Relaunched'
            $expected = "Import-Module 'C:\Modules\NSP.PKI\NSP.PKI.psd1'; Start-NSPPkiManager -CAConfigName 'ca01\Example''s CA'"
            Should -Invoke -ModuleName NSP.PKI Start-Process -Times 1 -ParameterFilter {
                $Verb -eq 'RunAs' -and $ArgumentList -contains '-EncodedCommand' -and
                [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ArgumentList[-1])) -eq $expected
            }
        }
    }
}

Describe 'Open-NSPOutputFolder' {
    BeforeEach {
        $script:SavedNoExplorer = $env:NSP_NO_EXPLORER
        $env:NSP_NO_EXPLORER = $null
        Mock -ModuleName NSP.PKI Start-Process { }
        Mock -ModuleName NSP.PKI Get-NSPDesktopUserSid { 'S-1-5-21-1-2-3-1001' }
        Mock -ModuleName NSP.PKI Grant-NSPFolderRead { }
        $script:Dir = Join-Path $TestDrive ('out_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $Dir | Out-Null
        $script:File = Join-Path $Dir 'Contoso_PKI_Response.json'
        '{}' | Set-Content -LiteralPath $File
    }
    AfterEach { $env:NSP_NO_EXPLORER = $script:SavedNoExplorer }

    It 'gives the desktop user read access, then opens Explorer on the hand-back folder' {
        InModuleScope NSP.PKI -Parameters @{ F = $File } { param($F) Open-NSPOutputFolder -Path $F }
        Should -Invoke -ModuleName NSP.PKI Grant-NSPFolderRead -Times 1 -Exactly -ParameterFilter { $Path -eq $Dir -and $Sid -eq 'S-1-5-21-1-2-3-1001' }
        Should -Invoke -ModuleName NSP.PKI Start-Process -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq 'explorer.exe' -and "$ArgumentList" -eq ('"{0}"' -f $Dir)
        }
    }
    It 'does nothing for a folder that was never written (dry run)' {
        InModuleScope NSP.PKI -Parameters @{ F = (Join-Path $TestDrive 'missing\x.json') } { param($F) Open-NSPOutputFolder -Path $F }
        Should -Invoke -ModuleName NSP.PKI Start-Process -Times 0
    }
    It 'does nothing with NSP_NO_EXPLORER=1' {
        $env:NSP_NO_EXPLORER = '1'
        InModuleScope NSP.PKI -Parameters @{ F = $File } { param($F) Open-NSPOutputFolder -Path $F }
        Should -Invoke -ModuleName NSP.PKI Start-Process -Times 0
    }
}

Describe 'Grant-NSPFolderRead' {
    It 'adds one read-only, inherited entry for that account (real ACL on a TestDrive folder)' {
        $dir = Join-Path $TestDrive ('acl_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        InModuleScope NSP.PKI -Parameters @{ D = $dir; S = $me } { param($D, $S) Grant-NSPFolderRead -Path $D -Sid $S }
        $ace = @((Get-Acl -LiteralPath $dir).Access | Where-Object { -not $_.IsInherited -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $me })
        $ace.Count | Should -Be 1
        "$($ace[0].FileSystemRights)" | Should -Match 'ReadAndExecute'
        "$($ace[0].FileSystemRights)" | Should -Not -Match 'Write|Modify|FullControl'
        "$($ace[0].InheritanceFlags)" | Should -Match 'ObjectInherit'
    }
    It 'warns instead of throwing when the folder is missing' {
        Mock -ModuleName NSP.PKI Write-Warning { }
        { InModuleScope NSP.PKI { Grant-NSPFolderRead -Path (Join-Path $TestDrive 'nope') -Sid 'S-1-5-18' } } | Should -Not -Throw
        Should -Invoke -ModuleName NSP.PKI Write-Warning -Times 1
    }
}