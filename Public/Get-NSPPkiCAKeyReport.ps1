function Get-NSPPkiCAKeyReport {
    <#
    .SYNOPSIS
        Reports which key a certificate authority is using: the SHA-256 fingerprint of the CA
        certificate's public key, its algorithm and size, and the key provider configured for
        the CA. Read-only. It never opens, exports or changes a private key.

    .DESCRIPTION
        Record PublicKeySha256 when a CA is created. Run this again after anything touches the CA
        or its key (a restore, a migration, a provider change, a renewal that was meant to keep
        the key) and compare. A different fingerprint means a different key, whatever the key size
        or the provider name says.

        With no parameters it reads this machine's CA. On a machine without one it returns a
        report whose Status is 'NoLocalCA'; it does not throw.

        Status values: Ok, NoLocalCA, CACertificateNotFound, CannotRead.

        ProviderClass is 'MicrosoftSoftware' for the built-in software providers, 'Other' for any
        other name and 'Unknown' when no name was read. 'Other' is not proof that the key is in
        hardware. KeyExportable is always empty: finding out would mean opening the private key,
        which this function does not do.

    .PARAMETER Certificate
        Report on this certificate instead of the local CA (for example an exported CA
        certificate, or the certificate in a request that came back signed).

    .PARAMETER CertificatePath
        Report on the certificate in this file (.cer / .crt, binary or Base64).

    .PARAMETER ExpectedPublicKeySha256
        The fingerprint recorded earlier. The report then says whether the key matches, in
        PublicKeyMatchesExpected.

    .EXAMPLE
        Get-NSPPkiCAKeyReport | Select-Object CACommonName, PublicKeySha256, PublicKeyBits, ProviderName, ProviderClass

    .EXAMPLE
        (Get-NSPPkiCAKeyReport -ExpectedPublicKeySha256 $recorded).PublicKeyMatchesExpected

    .EXAMPLE
        Get-NSPPkiCAKeyReport -CertificatePath .\EXAMPLE-ROOT-CA.cer
    #>
    [CmdletBinding(DefaultParameterSetName = 'LocalCA')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$CertificatePath,

        [string]$ExpectedPublicKeySha256
    )

    # A fingerprint that cannot be one is a caller mistake: say so, in every mode, before reading anything.
    if ($ExpectedPublicKeySha256 -and (($ExpectedPublicKeySha256 -replace '[\s:]', '') -notmatch '^[0-9A-Fa-f]{64}$')) {
        throw 'ExpectedPublicKeySha256 must be 64 hexadecimal characters.'
    }

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        $full = (Resolve-Path -LiteralPath $CertificatePath -ErrorAction Stop).ProviderPath
        # The byte-array constructor reads a certificate only; it never looks for a key.
        $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, [System.IO.File]::ReadAllBytes($full))
    }
    if ($Certificate) {
        return New-CAKeyReport -Status 'Ok' -Source 'Certificate' -Certificate $Certificate -ExpectedPublicKeySha256 $ExpectedPublicKeySha256
    }

    $configuration = $null
    try {
        $configuration = Get-CALocalKeyConfiguration
        if (-not $configuration) {
            return New-CAKeyReport -Status 'NoLocalCA' -Source 'LocalCA' -ExpectedPublicKeySha256 $ExpectedPublicKeySha256 -Detail 'This machine has no Certificate Services configuration.'
        }
        $local = if ($configuration.Thumbprint) { Get-CALocalCertificate -Thumbprint $configuration.Thumbprint } else { $null }
        if (-not $local) {
            return New-CAKeyReport -Status 'CACertificateNotFound' -Source 'LocalCA' -Configuration $configuration -ExpectedPublicKeySha256 $ExpectedPublicKeySha256 `
                -Detail 'The CA is configured, but its current certificate is not in the machine personal store.'
        }
        New-CAKeyReport -Status 'Ok' -Source 'LocalCA' -Certificate $local -Configuration $configuration -ExpectedPublicKeySha256 $ExpectedPublicKeySha256
    } catch {
        New-CAKeyReport -Status 'CannotRead' -Source 'LocalCA' -Configuration $configuration -ExpectedPublicKeySha256 $ExpectedPublicKeySha256 -Detail $_.Exception.Message
    }
}
