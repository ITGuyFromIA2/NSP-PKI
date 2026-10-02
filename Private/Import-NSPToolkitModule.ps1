function Import-NSPToolkitModule {
    <#
    .SYNOPSIS
        Loads a sibling NSP toolkit module on first use: an installed copy, else a checkout next to
        this repository (NSP-PoSHToolkits\NSP-X or GitRepo\NSP-X), else installs it from the
        PowerShell Gallery.
    .DESCRIPTION
        Copied from NSP.M365.ConditionalAccess, plus the second sibling location (NSP-Bootstrap
        lives directly under GitRepo, the others under NSP-PoSHToolkits). These modules are never
        RequiredModules entries, so this module still imports on a bare host. With
        -MinimumVersion, an older installed copy is passed over and a loaded older copy replaced.

        The Gallery install is what lets a plain `Install-Module NSP.<Tool>` work on its own: the
        siblings arrive the first time they're needed (AllUsers when elevated, else CurrentUser).
        NSP_NO_AUTOINSTALL=1 turns it off - the test runners set it so a test never reaches the
        network.
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
        Write-Host "Installing $wanted from the PowerShell Gallery..." -ForegroundColor DarkGray
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            $scope = if ($identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'AllUsers' } else { 'CurrentUser' }
            if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope $scope -ErrorAction Stop | Out-Null
            }
            $install = @{ Name = $Name; Repository = 'PSGallery'; Scope = $scope; Force = $true; AllowClobber = $true; ErrorAction = 'Stop' }
            if ($MinimumVersion) { $install.MinimumVersion = $MinimumVersion }
            Install-Module @install
            $path = & $findInstalled
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
