@{
    RootModule        = 'NSP.PKI.psm1'
    ModuleVersion     = '0.1.2'
    GUID              = 'fd050238-6af6-404d-a949-8fb31ac05dd0'
    Author            = 'Network Systems Plus'
    CompanyName       = 'Network Systems Plus'
    Copyright         = '(c) Network Systems Plus. All rights reserved.'
    Description       = 'Active Directory Certificate Services for NSP VPN deployments, plus the PKI Manager dashboard (CA install, templates, OCSP, TameMyCerts, App Proxy CRL/AIA publishing, FortiGate certificate hand-off). Windows PowerShell 5.1 compatible.'

    # 5.1 is the floor for every NSP toolkit, and the module must import on a bare 5.1 host -
    # sibling NSP modules are loaded on first use (Private\Import-NSPToolkitModule.ps1), never
    # declared as RequiredModules.
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'ConvertTo-NSPPkiAnswers'
        'Get-NSPPkiStatus'
        'Invoke-NSPPkiInventory'
        'New-NSPPkiShim'
        'Start-NSPPkiManager'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('NSP', 'PKI', 'ADCS', 'CertificateAuthority', 'VPN', 'FortiGate', 'Windows')
            ProjectUri   = 'https://github.com/ITGuyFromIA2/NSP-PKI'
            LicenseUri   = 'https://github.com/ITGuyFromIA2/NSP-PKI/blob/main/LICENSE'
            ReleaseNotes = 'https://github.com/ITGuyFromIA2/NSP-PKI/blob/main/CHANGELOG.md'
        }
    }
}