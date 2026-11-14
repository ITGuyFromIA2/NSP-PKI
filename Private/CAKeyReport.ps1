<#
    CA key identity, read-only. Everything here works from the PUBLIC half of a certificate and from
    configuration values. Nothing opens, exports, imports or changes a private key.

    Why it exists: a CA can be installed, backed up, restored or moved and still come back with a
    different key than the one that was intended, and a key-size label or a provider name does not
    prove otherwise. The fingerprint of the public key is the identity to record when a CA is
    created and to compare after anything touches it.
#>

function ConvertTo-CADerElement {
    # One DER element: tag, definite length, content. Pure.
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][byte]$Tag, [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Content)
    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.Add($Tag)
    $length = $Content.Length
    if ($length -lt 0x80) { $bytes.Add([byte]$length) }
    else {
        $lengthBytes = New-Object System.Collections.Generic.List[byte]
        for ($rest = $length; $rest -gt 0; $rest = $rest -shr 8) { $lengthBytes.Insert(0, [byte]($rest -band 0xFF)) }
        $bytes.Add([byte](0x80 -bor $lengthBytes.Count))
        $bytes.AddRange($lengthBytes)
    }
    $bytes.AddRange($Content)
    , $bytes.ToArray()
}

function ConvertTo-CADerObjectIdentifier {
    # A dotted object identifier as a DER element. Pure. Throws on anything that is not one.
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -notmatch '^[0-2](\.(0|[1-9][0-9]{0,17}))+$') { throw "Not an object identifier: '$Value'." }
    $arcs = @($Value.Split('.') | ForEach-Object { [uint64]$_ })
    if ($arcs[0] -lt 2 -and $arcs[1] -gt 39) { throw "Not an object identifier: '$Value'." }
    $content = New-Object System.Collections.Generic.List[byte]
    $numbers = @([uint64]($arcs[0] * 40 + $arcs[1])) + @($arcs | Select-Object -Skip 2)
    foreach ($number in $numbers) {
        # Base 128, most significant group first, high bit set on every group except the last.
        $groups = New-Object System.Collections.Generic.List[byte]
        $rest = [uint64]$number
        do { $groups.Insert(0, [byte]($rest -band 0x7F)); $rest = $rest -shr 7 } while ($rest -gt 0)
        for ($i = 0; $i -lt $groups.Count - 1; $i++) { $groups[$i] = [byte]($groups[$i] -bor 0x80) }
        $content.AddRange($groups)
    }
    ConvertTo-CADerElement -Tag 0x06 -Content $content.ToArray()
}

function Get-CAPublicKeyInfoDer {
    # The certificate's SubjectPublicKeyInfo as DER: algorithm identifier (with its parameters) and
    # the public key bits, exactly as the certificate carries them. Pure; public data only.
    # Built by hand because Windows PowerShell 5.1 has no export call for it. The tests compare it
    # with the .NET export where that exists and with fixed vectors checked by a second tool.
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $key = $Certificate.PublicKey
    $keyBytes = [byte[]]$key.EncodedKeyValue.RawData
    if (-not $keyBytes -or $keyBytes.Length -eq 0) { throw 'The certificate carries no public key bytes.' }
    $algorithm = New-Object System.Collections.Generic.List[byte]
    $algorithm.AddRange((ConvertTo-CADerObjectIdentifier -Value $key.Oid.Value))
    $parameters = $key.EncodedParameters.RawData
    if ($parameters -and $parameters.Length) { $algorithm.AddRange([byte[]]$parameters) }
    $bitString = New-Object System.Collections.Generic.List[byte]
    $bitString.Add([byte]0)     # no unused bits
    $bitString.AddRange($keyBytes)
    $body = New-Object System.Collections.Generic.List[byte]
    $body.AddRange((ConvertTo-CADerElement -Tag 0x30 -Content $algorithm.ToArray()))
    $body.AddRange((ConvertTo-CADerElement -Tag 0x03 -Content $bitString.ToArray()))
    ConvertTo-CADerElement -Tag 0x30 -Content $body.ToArray()
}

function Get-CAPublicKeyFingerprint {
    # SHA-256 of the SubjectPublicKeyInfo, lower-case hex. This identifies the key, not the
    # certificate: a renewed certificate on the same key keeps it, a replaced key does not.
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash((Get-CAPublicKeyInfoDer -Certificate $Certificate)) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
}

function Get-CAPublicKeyBits {
    # Key size from the public key. $null when the algorithm is neither RSA nor ECDSA.
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $public = $null
    try { $public = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate) } catch { $public = $null }
    if (-not $public) {
        try { $public = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Certificate) } catch { $public = $null }
    }
    if (-not $public) { return $null }
    try { [int]$public.KeySize } finally { $public.Dispose() }
}

function Get-CAProviderClass {
    # 'MicrosoftSoftware' for the providers that keep keys in software on this machine, 'Other' for
    # anything else, 'Unknown' for no name. 'Other' is NOT proof of hardware: a name proves nothing
    # about where a key lives. Pure.
    [OutputType([string])]
    param([string]$ProviderName)
    if ([string]::IsNullOrWhiteSpace($ProviderName)) { return 'Unknown' }
    $software = 'Microsoft Software Key Storage Provider', 'Microsoft Strong Cryptographic Provider', 'Microsoft Enhanced Cryptographic Provider v1.0',
        'Microsoft Enhanced RSA and AES Cryptographic Provider', 'Microsoft Base Cryptographic Provider v1.0', 'Microsoft RSA SChannel Cryptographic Provider'
    # Install-AdcsCertificationAuthority writes the name as "RSA#<provider>"; the registry holds the bare name.
    $bare = ($ProviderName -replace '^[A-Za-z0-9_]+#', '').Trim()
    if ($software -contains $bare) { 'MicrosoftSoftware' } else { 'Other' }
}

function Get-CALocalKeyConfiguration {
    # Reads the local CA's name, current certificate thumbprint and provider settings from the
    # Certificate Services configuration. $null when this machine has no CA. Read-only.
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    if (-not (Test-Path -LiteralPath $base)) { return $null }
    $active = [string](Get-ItemProperty -LiteralPath $base -ErrorAction Stop).Active
    if (-not $active) { return $null }
    $caKey = Join-Path $base $active
    if (-not (Test-Path -LiteralPath $caKey)) { return $null }
    $ca = Get-ItemProperty -LiteralPath $caKey -ErrorAction Stop
    # CACertHash lists one thumbprint per CA certificate, oldest first; the last usable one is current.
    $thumbprint = @(@($ca.CACertHash) | ForEach-Object { ([string]$_ -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() } | Where-Object { $_.Length -eq 40 }) | Select-Object -Last 1
    $csp = $null
    $cspKey = Join-Path $caKey 'CSP'
    if (Test-Path -LiteralPath $cspKey) { $csp = Get-ItemProperty -LiteralPath $cspKey -ErrorAction Stop }
    [pscustomobject]@{
        CACommonName       = $active
        Thumbprint         = $thumbprint
        ProviderName       = if ($csp) { [string]$csp.Provider } else { $null }
        HashAlgorithm      = if ($csp -and $csp.PSObject.Properties['CNGHashAlgorithm']) { [string]$csp.CNGHashAlgorithm } else { $null }
        PublicKeyAlgorithm = if ($csp -and $csp.PSObject.Properties['CNGPublicKeyAlgorithm']) { [string]$csp.CNGPublicKeyAlgorithm } else { $null }
    }
}

function Get-CALocalCertificate {
    # The certificate with this thumbprint from the machine's personal store, or $null. Read-only:
    # it returns the certificate object and never asks for its private key.
    param([Parameter(Mandatory)][string]$Thumbprint)
    $path = "Cert:\LocalMachine\My\$Thumbprint"
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    Get-Item -LiteralPath $path -ErrorAction Stop
}

function New-CAKeyReport {
    # Builds the report object. Pure: everything it uses is passed in.
    param(
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Source,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        $Configuration,
        [string]$ExpectedPublicKeySha256,
        [string]$Detail
    )
    $report = [ordered]@{
        Status = $Status; Source = $Source; CACommonName = $null
        Subject = $null; SerialNumber = $null; Thumbprint = $null; NotBefore = $null; NotAfter = $null
        PublicKeyAlgorithm = $null; PublicKeyBits = $null; PublicKeySha256 = $null
        ExpectedPublicKeySha256 = $null; PublicKeyMatchesExpected = $null
        ProviderName = $null; ProviderClass = 'Unknown'; ConfiguredHashAlgorithm = $null
        HasPrivateKeyReference = $null
        # Not checked on purpose: reading the export policy means opening the private key.
        KeyExportable = $null
        Detail = $Detail
    }
    if ($Configuration) {
        $report.CACommonName = $Configuration.CACommonName
        $report.ProviderName = $Configuration.ProviderName
        $report.ProviderClass = Get-CAProviderClass -ProviderName $Configuration.ProviderName
        $report.ConfiguredHashAlgorithm = $Configuration.HashAlgorithm
    }
    if ($Certificate) {
        $report.Subject = $Certificate.Subject
        $report.SerialNumber = $Certificate.SerialNumber
        $report.Thumbprint = $Certificate.Thumbprint
        $report.NotBefore = $Certificate.NotBefore
        $report.NotAfter = $Certificate.NotAfter
        $report.PublicKeyAlgorithm = if ($Certificate.PublicKey.Oid.FriendlyName) { $Certificate.PublicKey.Oid.FriendlyName } else { $Certificate.PublicKey.Oid.Value }
        $report.PublicKeyBits = Get-CAPublicKeyBits -Certificate $Certificate
        $report.PublicKeySha256 = Get-CAPublicKeyFingerprint -Certificate $Certificate
        $report.HasPrivateKeyReference = [bool]$Certificate.HasPrivateKey
    }
    if ($ExpectedPublicKeySha256) {
        $expected = ($ExpectedPublicKeySha256 -replace '[\s:]', '').ToLowerInvariant()
        if ($expected -notmatch '^[0-9a-f]{64}$') { throw 'ExpectedPublicKeySha256 must be 64 hexadecimal characters.' }
        $report.ExpectedPublicKeySha256 = $expected
        if ($report.PublicKeySha256) { $report.PublicKeyMatchesExpected = ($report.PublicKeySha256 -ceq $expected) }
    }
    [pscustomobject]$report
}
