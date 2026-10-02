<#
.SYNOPSIS
    Publishes NSP.PKI to the PowerShell Gallery (or another repository).

.DESCRIPTION
    Publish-Module -Path requires the source folder's name to exactly match the module name
    (the manifest's own basename). This repo's working directory is NSP-PKI (hyphen -
    matches the GitHub naming convention every NSP-* repo uses); the module's actual PowerShell
    identity is NSP.PKI (dot - matches standard module naming, e.g. Az.Accounts). That
    mismatch is why a direct `Publish-Module -Path C:\GitRepo\NSP-PoSHToolkits\NSP-PKI` fails with
    "no valid module was found with that path."

    This script stages a copy under the correct name in a temp directory and publishes from
    there, rather than renaming the real working directory (which is referenced by path all
    over this repo and its sibling NSP-* repos). Only runtime/user-facing content is staged -
    Tests\, tools\, and dev-only files (.gitignore, PSScriptAnalyzerSettings.psd1, CLAUDE.md)
    are not part of what an Install-Module user gets, so they're not included in the package.

.PARAMETER Repository
    The registered PSRepository to publish to. Defaults to 'PSGallery'. Point this at a local
    test repository (see about_Repositories) to dry-run the staging + publish path without
    touching the real Gallery.

.PARAMETER SecretName
    NSP secret holding the repository API key. Defaults to 'MS.PSGallery.ApiKey'.

.PARAMETER WhatIf
    Stage and validate (Test-ModuleManifest against the staged copy) but skip the actual
    publish call and the post-publish Find-Module verification.

.EXAMPLE
    .\tools\Publish-ToGallery.ps1

.EXAMPLE
    .\tools\Publish-ToGallery.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Repository = 'PSGallery',
    [string]$SecretName = 'MS.PSGallery.ApiKey'
)

$ErrorActionPreference = 'Stop'
$repoRoot   = Split-Path -Parent $PSScriptRoot
$moduleName = 'NSP.PKI'

$manifestPath = Join-Path $repoRoot "$moduleName.psd1"
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "Manifest not found: $manifestPath" }
$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath

# What actually ships to Install-Module users - runtime code + user-facing docs, not the dev
# tooling (Tests\, tools\, lint settings, AI-agent instructions) that only matters in this repo.
$publishItems = @(
    "$moduleName.psd1"
    "$moduleName.psm1"
    'Public'
    'Private'
    'Scripts'
    'README.md'
    'LICENSE'
    'CHANGELOG.md'
) | Where-Object { Test-Path -LiteralPath (Join-Path $repoRoot $_) }

$stageRoot       = Join-Path ([System.IO.Path]::GetTempPath()) ('NSPPKIPublish_' + [guid]::NewGuid().ToString('N'))
$stageModuleDir  = Join-Path $stageRoot $moduleName
# -WhatIf:$false on every staging operation below: this script's own -WhatIf/-Confirm would
# otherwise auto-propagate to New-Item/Copy-Item (they support ShouldProcess too), which
# would silently skip the staging and validation entirely instead of just skipping the real
# publish. Staging into a throwaway temp dir isn't the operation worth previewing - only the
# actual Publish-Module call, gated below, is.
New-Item -ItemType Directory -Path $stageModuleDir -Force -WhatIf:$false | Out-Null

try {
    foreach ($item in $publishItems) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $item) -Destination (Join-Path $stageModuleDir $item) -Recurse -Force -WhatIf:$false
    }
    Write-Host "Staged $moduleName $($manifest.ModuleVersion) at $stageModuleDir" -ForegroundColor DarkGray

    # Fails loudly here, before anything touches the network, if the staged copy is somehow
    # incomplete or the manifest doesn't parse.
    $null = Test-ModuleManifest -Path (Join-Path $stageModuleDir "$moduleName.psd1") -ErrorAction Stop
    Write-Host "Staged manifest OK." -ForegroundColor DarkGray

    # Requires Microsoft.PowerShell.PSResourceGet - the actively maintained Gallery client, not
    # the legacy PowerShellGet/PackageManagement stack. That stack failed two different ways
    # trying to publish this exact module (confirmed live 2026-09):
    #   1. The in-box PowerShellGet 1.0.0.1 can't publish at all - PSGallery now requires NuGet
    #      client 4.1.0+, which 1.0.0.1 doesn't speak (HTTP 400). Worse: 1.0.0.1's Publish-Module
    #      prints "Published X to Y" anyway regardless of whether it worked, so the failure looks
    #      like success unless you're watching for the red text.
    #   2. Forcing PowerShellGet 2.2.5 explicitly (bypassing 1.0.0.1) hits a SECOND bug one layer
    #      down: PowerShellGet 2.2.5's Publish-Module calls Find-Script -AllowPrereleaseVersions
    #      internally, a parameter that doesn't exist on this machine's PackageManagement
    #      (checked up to 1.4.8.1, the newest available) - ParameterBindingException, no publish
    #      at all. Not an auto-load problem this time; that PowerShellGet build genuinely wants a
    #      newer PackageManagement than what's installed.
    # PSResourceGet doesn't go through either of those - it talks to the Gallery directly on the
    # modern NuGet v3 API. Hard-fail rather than fall back to the legacy path a third time.
    $psResourceGet = Get-Module -ListAvailable -Name Microsoft.PowerShell.PSResourceGet -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1

    if (-not $psResourceGet) {
        throw "Microsoft.PowerShell.PSResourceGet is required (the legacy PowerShellGet path is unreliable on this machine - see the comment above this check). Install it:`n  Install-NSPModule -Name Microsoft.PowerShell.PSResourceGet"
    }

    if ($PSCmdlet.ShouldProcess("$moduleName $($manifest.ModuleVersion) -> $Repository", 'Publish')) {
        # Only touches the secret store / network on a real (non -WhatIf) run.
        $NSPBootstrapManifest = 'C:\GitRepo\NSP-Bootstrap\NSP.Bootstrap.psd1'
        if (Test-Path $NSPBootstrapManifest) { Import-Module $NSPBootstrapManifest -Force -ErrorAction Stop }
        else { Import-Module NSP.Bootstrap -Force -ErrorAction Stop }
        $apiKey = Get-NSPSecret -Name $SecretName -AsPlainText

        Import-Module Microsoft.PowerShell.PSResourceGet -RequiredVersion $psResourceGet.Version -Force -ErrorAction Stop
        Write-Host "Publishing via Microsoft.PowerShell.PSResourceGet $($psResourceGet.Version)..." -ForegroundColor DarkGray
        Publish-PSResource -Path $stageModuleDir -ApiKey $apiKey -Repository $Repository -ErrorAction Stop

        # Trust but verify - the legacy tooling has already been caught reporting success on a
        # run that actually failed. Confirm the version is really there before calling it done.
        Write-Host "Verifying..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 5
        $found = Find-PSResource -Name $moduleName -Version $manifest.ModuleVersion -Repository $Repository -ErrorAction SilentlyContinue
        if ($found) {
            Write-Host "Confirmed: $moduleName $($manifest.ModuleVersion) is live on $Repository." -ForegroundColor Green
        } else {
            Write-Warning "Publish-PSResource reported success, but Find-PSResource can't see $moduleName $($manifest.ModuleVersion) on $Repository yet. This can be Gallery indexing lag (retry in a minute or two) or a genuine failure - don't assume it worked without checking https://www.powershellgallery.com/packages/$moduleName."
        }
    }
} finally {
    # Real cleanup even under -WhatIf, for the same reason staging above forces -WhatIf:$false -
    # otherwise every -WhatIf run leaves its temp directory behind.
    Remove-Item -LiteralPath $stageRoot -Recurse -Force -WhatIf:$false -ErrorAction SilentlyContinue
}
