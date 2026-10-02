<#
    NSP.PKI - module loader. Dot-sources Private\ then Public\, exports only Public.
#>

$script:ModuleRoot = $PSScriptRoot

$private = @( Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue )
$public  = @( Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue )

foreach ($file in @($private + $public)) {
    try {
        . $file.FullName
    } catch {
        throw "NSP.PKI: failed to load $($file.FullName): $_"
    }
}

Export-ModuleMember -Function $public.BaseName