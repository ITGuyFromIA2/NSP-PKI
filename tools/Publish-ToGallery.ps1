<#
.SYNOPSIS
    Publishes NSP.PKI to the PowerShell Gallery (or another repository).

.DESCRIPTION
    Runs Publish-NSPModule from NSP.RepoTools, the release routine every NSP module shares. It
    checks the manifest, changelog, clean working tree, Gallery version, client references (Git
    history included), and tools\Test-Repo.ps1; packages tracked runtime files only, under the
    module's name; publishes with PSResourceGet; confirms the version is live; and tags
    v<version> locally. Nothing is published unless every check passes.

.PARAMETER Repository
    The registered PSRepository to publish to. Defaults to 'PSGallery'.

.PARAMETER SecretName
    NSP secret holding the repository API key. Defaults to 'MS.PSGallery.ApiKey'.

.EXAMPLE
    .\tools\Publish-ToGallery.ps1 -WhatIf

.EXAMPLE
    .\tools\Publish-ToGallery.ps1
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$Repository = 'PSGallery',
    [string]$SecretName = 'MS.PSGallery.ApiKey'
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Command Publish-NSPModule -ErrorAction SilentlyContinue)) {
    if (-not (Get-Module -ListAvailable -Name NSP.RepoTools)) {
        throw 'NSP.RepoTools is required: Install-NSPModule -Name NSP.RepoTools'
    }
    Import-Module NSP.RepoTools
}

$publish = @{ Path = (Split-Path -Parent $PSScriptRoot); Repository = $Repository; SecretName = $SecretName }
foreach ($name in 'WhatIf', 'Confirm') { if ($PSBoundParameters.ContainsKey($name)) { $publish[$name] = $PSBoundParameters[$name] } }
Publish-NSPModule @publish