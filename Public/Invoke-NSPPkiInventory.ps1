function Invoke-NSPPkiInventory {
    <#
    .SYNOPSIS
        Runs the full read-only CA inventory (PKI Manager menu 14): CA configuration, templates and
        their permissions, OCSP, CRL share, AIA/CDP, auto-enrollment GPOs, group membership. Writes a
        report to -OutputDir. Relaunches elevated if needed.

    .PARAMETER OutputDir
        Where the report goes.

    .PARAMETER TemplateName
        Templates to report on in detail.

    .PARAMETER CrlSharePath
        The CRL distribution share to check.

    .PARAMETER MasterGroupName
        The auto-enrollment umbrella group; without it the AD section searches by wildcard.

    .EXAMPLE
        Invoke-NSPPkiInventory -OutputDir C:\Temp\CAInventory
    #>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "C:\Admin\CAInventory",
        [string[]]$TemplateName,
        [string]$CrlSharePath,
        [string]$MasterGroupName
    )
    & (Join-Path $script:ModuleRoot 'Scripts\Get-CAManagerInventory.ps1') @PSBoundParameters
}
