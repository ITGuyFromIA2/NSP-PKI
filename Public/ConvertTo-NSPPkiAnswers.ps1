function ConvertTo-NSPPkiAnswers {
    <#
    .SYNOPSIS
        Turns one client's ClientAnswers (the Orchestrator's ClientAnswers\<Abbrev>.json) into the
        answers PKI Manager reads - the same fields the Orchestrator's CA staging embedded in the
        zip-era CA-Manager launcher. Returns $null for a client that doesn't use certificate auth.

    .DESCRIPTION
        Carries Company_Name (the name PKI Manager reads), Cert_CertificateName, Cert_PeerName, RadiusGroupPairs (the per-group
        templates and TameMyCerts policy need them) and every CA_* field the client has.

    .PARAMETER ClientAnswers
        A ClientAnswers object, or the path to a ClientAnswers .json file.

    .EXAMPLE
        ConvertTo-NSPPkiAnswers -ClientAnswers 'C:\...\ClientAnswers\EXAMPLE.json' | ConvertTo-Json
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory, ValueFromPipeline)][object]$ClientAnswers)

    process {
        $a = $ClientAnswers
        if ($a -is [string]) {
            if (-not (Test-Path -LiteralPath $a)) { throw "ClientAnswers file not found: $a" }
            $a = Get-Content -LiteralPath $a -Raw | ConvertFrom-Json
        }
        if ("$($a.AuthMethod)" -ne 'Certificate') { return $null }

        $payload = [ordered]@{
            Company_Name         = $a.Company_Name
            Cert_CertificateName = $a.Cert_CertificateName
            Cert_PeerName        = $a.Cert_PeerName
        }
        if ($a.PSObject.Properties['RadiusGroupPairs'] -and $a.RadiusGroupPairs) { $payload['RadiusGroupPairs'] = $a.RadiusGroupPairs }
        foreach ($prop in $a.PSObject.Properties) {
            if ($prop.Name -like 'CA_*') { $payload[$prop.Name] = $prop.Value }
        }
        [pscustomobject]$payload
    }
}
