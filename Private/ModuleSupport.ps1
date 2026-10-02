<#
    ModuleSupport.ps1 - NSP.PKI glue between the zip-era CA Manager code (the other Private files,
    moved with only small, marked edits) and the module world: the work-folder answers file, the
    module version, and updating the module from the Gallery (the zip-era "U" re-ran its shim).
#>

function Set-PKIToolAnswerField {
    # Sets one field in the PKI work folder's Answers.json - the CA configuration name the zip-era
    # launcher kept in its own $CAServerName line is saved here instead (PKICAConfigName).
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Field, [AllowNull()]$Value)
    $answers = $null
    if (Test-Path -LiteralPath $Path) {
        $raw = [IO.File]::ReadAllText($Path)
        if (-not [string]::IsNullOrWhiteSpace($raw)) { $answers = ConvertFrom-Json -InputObject $raw }
    }
    if ($null -eq $answers) { $answers = New-Object psobject }
    $answers | Add-Member -NotePropertyName $Field -NotePropertyValue $Value -Force
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $answers -Depth 20), (New-Object Text.UTF8Encoding($false)))
}

function Repair-PKIAnswerField {
    # Answers from the Orchestrator's zip-era CA staging carry CompanyName; the engine reads
    # Company_Name, so without this menu 13 asked for a company it had already been given.
    param([AllowNull()]$CAAnswers)
    if ($CAAnswers -and $CAAnswers.PSObject.Properties['CompanyName'] -and
        [string]::IsNullOrWhiteSpace([string]$CAAnswers.Company_Name) -and -not [string]::IsNullOrWhiteSpace([string]$CAAnswers.CompanyName)) {
        $CAAnswers | Add-Member -NotePropertyName Company_Name -NotePropertyValue ([string]$CAAnswers.CompanyName) -Force
    }
    return $CAAnswers
}

function Get-NSPPkiModuleVersion {
    return [string]$ExecutionContext.SessionState.Module.Version
}

function Get-PKIExpectedTemplate {
    # The header's "custom templates" line: the ISSUANCE templates only (user/device/FortiGate) - the
    # OCSP signing template's state shows under the OCSP responder line instead. Same as the zip-era
    # CA-Manager.ps1 startup block.
    param($CAAnswers)
    $expected = @('IKEv2VPN-InternalUsers', 'IKEv2VPN-InternalUsers-MANUAL', 'FortiGate')
    if ($CAAnswers) {
        $fromAnswers = @(
            $CAAnswers.CA_TemplateAuto,
            $CAAnswers.CA_TemplateManual,
            $CAAnswers.CA_TemplateFortiGate
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if (@($fromAnswers).Count) { $expected = @($fromAnswers) }
    }
    return $expected
}

function Invoke-PKIModuleUpdate {
    # Menu U. The zip-era U re-ran the staged shim to fetch a newer CAManager.zip; the module
    # equivalent installs a newer NSP.PKI from the PowerShell Gallery (machine-wide) and relaunches.
    param([string]$CAConfigName)
    $current = [version](Get-NSPPkiModuleVersion)
    Write-Host "`n  NSP.PKI $current is running. Checking the PowerShell Gallery..." -ForegroundColor Cyan
    $found = $null
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $found = Find-Module -Name NSP.PKI -Repository PSGallery -ErrorAction Stop
    } catch {
        Write-Host "  Could not reach the PowerShell Gallery: $($_.Exception.Message)" -ForegroundColor Yellow
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }
    if ([version]$found.Version -le $current) {
        Write-Host "  Already up to date (the Gallery has $($found.Version))." -ForegroundColor Green
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }
    if (-not (Read-CAConfirm -Prompt "Install NSP.PKI $($found.Version) (machine-wide) and relaunch now?" -DefaultYes)) { return }
    Install-Module -Name NSP.PKI -RequiredVersion $found.Version -Repository PSGallery -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
    $installed = Get-Module -ListAvailable -Name NSP.PKI | Sort-Object Version -Descending | Select-Object -First 1
    Invoke-CAManagerRelaunch -ScriptPath $installed.Path -CAConfigName $CAConfigName
}
