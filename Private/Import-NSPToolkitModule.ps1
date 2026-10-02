# Shared sibling-module loader. CANONICAL COPY: NSP-Toolkit\Private\Import-NSPToolkitModule.ps1.
# NSP.ActiveDirectory / NSP.NPS / NSP.PKI / NSP.FortiClient carry generated copies - edit this file,
# then run NSP-Toolkit\tools\Sync-SharedLoader.ps1. Each repo's tests fail when its copy drifts.
function Import-NSPToolkitModule {
    <#
    .SYNOPSIS
        Loads a sibling NSP toolkit module on first use: an installed copy, else a checkout next to
        this repository (NSP-PoSHToolkits\NSP-X or GitRepo\NSP-X), else installs it from the
        PowerShell Gallery.
    .DESCRIPTION
        These modules are never RequiredModules entries, so each module still imports on a bare
        host. With -MinimumVersion, an older installed copy is passed over and a loaded older copy
        replaced.

        The Gallery install is what lets a plain `Install-Module NSP.<Tool>` work on its own: the
        siblings arrive the first time they're needed. It is announced before it happens (module,
        version, scope - AllUsers when elevated, else CurrentUser) and reported after.
        NSP_NO_AUTOINSTALL=1 turns it off and fails with the Install-Module command to run instead;
        the test runners set it so a test never reaches the network.

        The import is -Global on purpose: NSP.Toolkit holds session-wide state (the dry-run switch,
        work-folder paths, tool versions) that every tool module must share, and a module-scoped
        import per caller could leave two different versions loaded in one session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [version]$MinimumVersion,
        [switch]$Reload
    )

    $loaded = Get-Module -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    if ($loaded -and -not $Reload -and (-not $MinimumVersion -or $loaded.Version -ge $MinimumVersion)) { return }
    $findInstalled = {
        $m = Get-Module -ListAvailable -Name $Name | Where-Object { -not $MinimumVersion -or $_.Version -ge $MinimumVersion } |
            Sort-Object Version -Descending | Select-Object -First 1
        if ($m) { $m.Path }
    }
    $path = & $findInstalled
    if (-not $path) {
        $folder = $Name.Replace('.', '-')
        $toolkits = Split-Path -Parent $script:ModuleRoot
        foreach ($candidate in @((Join-Path $toolkits "$folder\$Name.psd1"), (Join-Path (Split-Path -Parent $toolkits) "$folder\$Name.psd1"))) {
            if (-not (Test-Path -LiteralPath $candidate)) { continue }
            if ($MinimumVersion -and [version](Import-PowerShellDataFile -LiteralPath $candidate).ModuleVersion -lt $MinimumVersion) { continue }
            $path = $candidate
            break
        }
    }
    $wanted = if ($MinimumVersion) { "$Name $MinimumVersion or later" } else { $Name }
    $installError = $null
    if (-not $path -and $env:NSP_NO_AUTOINSTALL -ne '1') {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            $scope = if ($identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'AllUsers' } else { 'CurrentUser' }
            Write-Host "$wanted is needed and not installed - installing it from the PowerShell Gallery (scope $scope)..." -ForegroundColor Cyan
            if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
                Write-Host "  Installing the NuGet package provider first (scope $scope)." -ForegroundColor DarkGray
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope $scope -ErrorAction Stop | Out-Null
            }
            $install = @{ Name = $Name; Repository = 'PSGallery'; Scope = $scope; Force = $true; AllowClobber = $true; ErrorAction = 'Stop' }
            if ($MinimumVersion) { $install.MinimumVersion = $MinimumVersion }
            Install-Module @install
            $path = & $findInstalled
            if ($path) {
                $got = (Import-PowerShellDataFile -LiteralPath $path).ModuleVersion
                Write-Host "  Installed $Name $got ($scope)." -ForegroundColor DarkGray
            }
        } catch {
            $installError = $_.Exception.Message
        }
    }
    if (-not $path) {
        $why = if ($installError) { " Installing it from the PowerShell Gallery failed: $installError" } else { '' }
        throw "$wanted is required for this operation.$why Install it (Install-Module $Name), or check out $($Name.Replace('.', '-')) next to this repository."
    }
    if ($loaded) { Remove-Module -Name $Name -Force }
    Import-Module $path -Global -ErrorAction Stop
}
