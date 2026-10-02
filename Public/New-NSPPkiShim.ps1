function New-NSPPkiShim {
    <#
    .SYNOPSIS
        Writes a launcher script for PKI Manager - optionally carrying a client's CA answers - to drop
        on the issuing CA and run.

    .DESCRIPTION
        The launcher installs NSP.PKI (this version or newer) and the NSP modules it uses from the
        PowerShell Gallery, hands the answers to Start-NSPPkiManager once, blanks them from its own
        file, and starts the dashboard. See New-NSPToolShim (NSP.ClientScripts).

    .PARAMETER Answers
        PKI answers (ConvertTo-NSPPkiAnswers output), a hashtable, or a JSON string. Optional.

    .PARAMETER ClientAnswers
        A ClientAnswers object or file instead of -Answers; converted with ConvertTo-NSPPkiAnswers.

    .PARAMETER Path
        Where to write the launcher (.ps1).

    .PARAMETER Company
        Shown in the launcher header; defaults to the answers' Company_Name.

    .PARAMETER GeneratedBy
        Shown in the launcher header, e.g. 'Orchestrator 4.1.0'.

    .PARAMETER Force
        Overwrite an existing file.

    .EXAMPLE
        New-NSPPkiShim -ClientAnswers 'C:\...\ClientAnswers\EXAMPLE.json' -Path C:\Temp\PKI-Manager.ps1
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Answers')]
    [OutputType([IO.FileInfo])]
    param(
        [Parameter(ParameterSetName = 'Answers')][object]$Answers,
        [Parameter(Mandatory, ParameterSetName = 'ClientAnswers')][object]$ClientAnswers,
        [Parameter(Mandatory)][string]$Path,
        [string]$Company,
        [string]$GeneratedBy,
        [switch]$Force
    )

    Import-NSPToolkitModule -Name NSP.ClientScripts -MinimumVersion 0.1.0
    if ($PSCmdlet.ParameterSetName -eq 'ClientAnswers') {
        $Answers = ConvertTo-NSPPkiAnswers -ClientAnswers $ClientAnswers
        if ($null -eq $Answers) { throw 'That client does not use certificate authentication (AuthMethod is not Certificate) - there is nothing for PKI Manager.' }
    }
    if ($Answers -is [string]) {
        try { $Answers = ConvertFrom-Json -InputObject $Answers -ErrorAction Stop }
        catch { throw "-Answers is not valid JSON: $($_.Exception.Message)" }
    }
    if (-not $Company -and $Answers) {
        foreach ($key in 'Company_Name', 'CompanyName') {
            $value = if ($Answers -is [Collections.IDictionary]) { [string]$Answers[$key] } elseif ($Answers.PSObject.Properties[$key]) { [string]$Answers.$key } else { '' }
            if ($value) { $Company = $value; break }
        }
    }

    $version = Get-NSPPkiModuleVersion
    $shim = @{
        ToolName             = 'PKI Manager'
        ModuleName           = 'NSP.PKI'
        ModuleMinimumVersion = $version
        EntryFunction        = 'Start-NSPPkiManager'
        Modules              = @(
            @{ Name = 'NSP.Console'; MinimumVersion = '0.1.2' }
            @{ Name = 'NSP.Toolkit'; MinimumVersion = '0.1.0' }
            @{ Name = 'NSP.PKI'; MinimumVersion = $version }
        )
        Path                 = $Path
        Force                = $Force
    }
    if ($null -ne $Answers) { $shim['SeedAnswers'] = $Answers }
    if ($Company) { $shim['Company'] = $Company }
    if ($GeneratedBy) { $shim['GeneratedBy'] = $GeneratedBy }

    if ($PSCmdlet.ShouldProcess($Path, 'Write PKI Manager launcher')) {
        New-NSPToolShim @shim -Confirm:$false
    }
}
