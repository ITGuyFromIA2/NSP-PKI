function Get-NSPPkiStatus {
    <#
    .SYNOPSIS
        A snapshot of this server's certificate authority setup - CA identity and expiry, OCSP
        responder, custom templates, AIA/CDP/OCSP publishing, CRL share, auto-enrollment, App Proxy
        connector and the derived issuance readiness - the same facts the PKI Manager dashboard shows
        at the top. Read-only; usable from RMM.

    .PARAMETER CAConfigName
        The CA configuration to check. Blank = the local CA.

    .PARAMETER ExpectedTemplates
        Template display names to report on. Defaults to the saved PKI answers' templates, else the
        standard VPN set.

    .EXAMPLE
        Get-NSPPkiStatus | Select-Object CACommonName, IssuanceReady
    #>
    [CmdletBinding()]
    param(
        [string]$CAConfigName,
        [string[]]$ExpectedTemplates
    )
    if (-not $ExpectedTemplates) {
        $saved = $null
        if (Get-Command Get-NSPToolAnswers -ErrorAction SilentlyContinue) { $saved = Get-NSPToolAnswers -Tool PKI }
        $ExpectedTemplates = Get-PKIExpectedTemplate -CAAnswers $saved
    }
    Get-CAStatus -CAConfigName $CAConfigName -ExpectedTemplates $ExpectedTemplates
}
