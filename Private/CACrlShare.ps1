<#
.SYNOPSIS
    CA Manager - menu 7 (2026-09-10 renumber - was menu 6). Creates the CRL distribution SMB share
    (+ its ACLs and the infra AD group) for a split-tier / segregated-proxy deployment. Gated on
    CA_CrlShareMode.

.DESCRIPTION
    Single-tier co-located CA (CA_CrlShareMode = None): NOT needed - the CA writes its own CRL to
    %windir%\...\CertEnroll and IIS (menu 6) serves it directly. Menu 7 is a no-op there.

    Split-tier (RootCrlPublish) or segregated App Proxy box (SegregatedProxy): the CA publishes its
    CRL/AIA to a share the proxy/IIS box can read. Reproduces a real client's hand-built C:\CRLShare
    (from a captured CA inventory, section G):
      - SMB share "CRLShare" -> C:\CRLShare
      - share ACL: <WriteGroup> = Full  (the only non-default entry)
      - NTFS: <WriteGroup> = FullControl, plus ALL APPLICATION PACKAGES = ReadAndExecute
        (that last is what lets the co-located IIS / App Proxy worker read the .crl/.crt files)
      - infra AD group (default CA_CRLPublishers) whose member is the publishing CA's machine account

    Get-CACrlSharePlan is PURE. New-CACrlShare routes every mutation through Invoke-CAStep. After
    menu 7, run menu 8 - Get-CAPublicationUrlPlan already appends the file://<share>/... CDP entry
    when CA_CrlSharePath is set.
#>

# ---------------------------------------------------------------------------
function Get-CACrlSharePlan {
    <#
    .SYNOPSIS
        PURE. Turns the CA_CrlShare* answers into the share/ACL/AD-group plan. No I/O.
    #>
    param(
        [Parameter(Mandatory)]$CAAnswers,
        [string]$CAMachineName = $env:COMPUTERNAME
    )
    $mode = if ($CAAnswers.CA_CrlShareMode) { "$($CAAnswers.CA_CrlShareMode)" } else { 'None' }

    if ($mode -notin @('RootCrlPublish', 'SegregatedProxy')) {
        return [pscustomobject]@{
            Mode = $mode; Applicable = $false
            Reason = "CA_CrlShareMode is '$mode' - a single-tier co-located CA serves its CRL from its own CertEnroll dir via IIS (menu 6). Nothing to do here."
        }
    }

    $sharePath = if (-not [string]::IsNullOrWhiteSpace($CAAnswers.CA_CrlSharePath)) {
        ($CAAnswers.CA_CrlSharePath).TrimEnd('\', '/')
    } else { 'C:\CRLShare' }
    # UNC form: if the answer is already \\server\share keep it; else \\<thisbox>\<leaf>
    $isUnc     = $sharePath -match '^\\\\'
    $shareName = if ($isUnc) { ($sharePath -split '\\')[-1] } else { Split-Path $sharePath -Leaf }
    $localPath = if ($isUnc) { $null } else { $sharePath }
    $uncPath   = if ($isUnc) { $sharePath } else { "\\$CAMachineName\$shareName" }

    $writeGroup = if (-not [string]::IsNullOrWhiteSpace($CAAnswers.CA_CrlShareWriteGroup)) {
        "$($CAAnswers.CA_CrlShareWriteGroup)"
    } else { 'CA_CRLPublishers' }

    [pscustomobject]@{
        Mode        = $mode
        Applicable  = $true
        ShareName   = $shareName
        LocalPath   = $localPath          # $null when the answer was a bare UNC (share lives on another box)
        UncPath     = $uncPath
        WriteGroup  = $writeGroup
        ShareAccess = [pscustomobject]@{ Account = $writeGroup; Right = 'Full' }
        NtfsAces    = @(
            [pscustomobject]@{ Account = $writeGroup; Right = '(OI)(CI)F' }                       # FullControl, inherited to files+dirs
            [pscustomobject]@{ Account = 'ALL APPLICATION PACKAGES'; Right = '(OI)(CI)(RX)' }      # IIS / App Proxy worker read
        )
        InfraGroupName    = $writeGroup
        InfraGroupSamName = ($writeGroup -replace '[^A-Za-z0-9_\-]', '')
        InfraGroupMember  = "$CAMachineName`$"     # the publishing CA's machine account
        Notes = "Transcribed from a real client's C:\CRLShare. After this, run menu 8 - it appends the file://<share>/%3%8%9.crl CDP entry when CA_CrlSharePath is set."
    }
}

# ---------------------------------------------------------------------------
function Show-CACrlSharePlan {
    param([Parameter(Mandatory)]$Plan)
    if (-not $Plan.Applicable) {
        Write-Host "  $($Plan.Reason)" -ForegroundColor Gray
        return
    }
    Write-Host ("  Mode          : {0}" -f $Plan.Mode) -ForegroundColor White
    Write-Host ("  Share         : {0}  ->  {1}" -f $Plan.ShareName, $(if ($Plan.LocalPath) { $Plan.LocalPath } else { '(on another host - ' + $Plan.UncPath + ')' })) -ForegroundColor Gray
    Write-Host ("  Share ACL     : {0} = {1}" -f $Plan.ShareAccess.Account, $Plan.ShareAccess.Right) -ForegroundColor Gray
    foreach ($a in $Plan.NtfsAces) { Write-Host ("  NTFS ACE      : {0} : {1}" -f $a.Account, $a.Right) -ForegroundColor Gray }
    Write-Host ("  Infra group   : {0}  (member: {1})" -f $Plan.InfraGroupName, $Plan.InfraGroupMember) -ForegroundColor Gray
    Write-Host ("  UNC           : {0}" -f $Plan.UncPath) -ForegroundColor Gray
    Write-Host ("  Then          : run menu 8 (it adds the file://<share> CDP entry from CA_CrlSharePath)") -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
function New-CACrlShare {
    <#
    .SYNOPSIS
        ENGINE. Creates the CRL share directory + SMB share + ACLs + the infra AD group from a
        Get-CACrlSharePlan. Every mutation via Invoke-CAStep. Tolerates each piece already existing.
    #>
    param([Parameter(Mandatory)]$Plan)

    if (-not $Plan.Applicable) {
        Write-Host "  $($Plan.Reason)" -ForegroundColor Gray
        return
    }

    # 1. AD infra group + the CA machine account
    Invoke-CAStep -Description "Ensure AD group '$($Plan.InfraGroupSamName)' exists and holds $($Plan.InfraGroupMember)" `
        -Commands @(
            "New-ADGroup -Name '$($Plan.InfraGroupSamName)' -GroupScope Global -GroupCategory Security"
            "Add-ADGroupMember -Identity '$($Plan.InfraGroupSamName)' -Members (Get-ADComputer '$env:COMPUTERNAME')"
        ) `
        -Action {
            if (-not (Get-Command Get-ADGroup -ErrorAction SilentlyContinue)) { throw "ActiveDirectory module not available - run menu 1, or create '$($Plan.InfraGroupSamName)' by hand." }
            $g = Get-ADGroup -LDAPFilter "(sAMAccountName=$($Plan.InfraGroupSamName))" -ErrorAction SilentlyContinue
            if (-not $g) { New-ADGroup -Name $Plan.InfraGroupSamName -SamAccountName $Plan.InfraGroupSamName -GroupScope Global -GroupCategory Security -Description 'CRL/AIA publish identity for a split-tier CA (CA-Manager menu 7)' }
            $comp = Get-ADComputer -Identity $env:COMPUTERNAME -ErrorAction Stop
            $members = @(Get-ADGroupMember -Identity $Plan.InfraGroupSamName -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value })
            if ($members -notcontains $comp.SID.Value) { Add-ADGroupMember -Identity $Plan.InfraGroupSamName -Members $comp }
        } -ContinueOnError | Out-Null

    if (-not $Plan.LocalPath) {
        Write-Host "  CA_CrlSharePath is a bare UNC ($($Plan.UncPath)) - the share lives on another host; create the directory / share / ACLs there. Group step above still applies." -ForegroundColor Yellow
        return
    }

    # 2. directory
    Invoke-CAStep -Description "Create the CRL share directory $($Plan.LocalPath)" `
        -Commands @("New-Item -ItemType Directory -Path '$($Plan.LocalPath)' -Force") `
        -Action { if (-not (Test-Path $Plan.LocalPath)) { New-Item -ItemType Directory -Path $Plan.LocalPath -Force | Out-Null } } | Out-Null

    # 3. SMB share + share-level ACL
    Invoke-CAStep -Description "Create SMB share '$($Plan.ShareName)' -> $($Plan.LocalPath) and grant $($Plan.ShareAccess.Account) Full" `
        -Commands @(
            "New-SmbShare -Name '$($Plan.ShareName)' -Path '$($Plan.LocalPath)' -FullAccess '$($Plan.ShareAccess.Account)'"
            "Grant-SmbShareAccess -Name '$($Plan.ShareName)' -AccountName '$($Plan.ShareAccess.Account)' -AccessRight Full -Force"
        ) `
        -Action {
            $existing = Get-SmbShare -Name $Plan.ShareName -ErrorAction SilentlyContinue
            if (-not $existing) {
                New-SmbShare -Name $Plan.ShareName -Path $Plan.LocalPath -FullAccess $Plan.ShareAccess.Account | Out-Null
            } else {
                Grant-SmbShareAccess -Name $Plan.ShareName -AccountName $Plan.ShareAccess.Account -AccessRight Full -Force | Out-Null
            }
        } -ContinueOnError | Out-Null

    # 4. NTFS ACEs (icacls - deterministic + previewable)
    foreach ($ace in $Plan.NtfsAces) {
        Invoke-CAStep -Description "NTFS: grant '$($ace.Account)' '$($ace.Right)' on $($Plan.LocalPath)" `
            -Commands @("icacls `"$($Plan.LocalPath)`" /grant `"$($ace.Account):$($ace.Right)`"") `
            -Action {
                $o = & icacls.exe $Plan.LocalPath /grant "$($ace.Account):$($ace.Right)" 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0) { throw "icacls failed (exit $LASTEXITCODE): $o" }
                $o
            } -ContinueOnError | Out-Null
    }

    Write-Host ""
    Write-Host "  CRL share ready. Next: run menu 8 so the CA publishes to file://$($Plan.LocalPath -replace '\\','/')/... too" -ForegroundColor Cyan
    Write-Host "  (Get-CAPublicationUrlPlan adds that entry when CA_CrlSharePath is set)." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
function Invoke-CAMenuCrlShare {
    <#
    .SYNOPSIS
        Menu 7 (2026-09-10 renumber - was menu 6). Creates the CRL distribution share for a split-tier deployment. No-op for a
        single-tier co-located CA (CA_CrlShareMode = None).
    #>
    param(
        $CAAnswers,
        $Status
    )
    Write-CAHeader "CRL distribution share + AD group"
    if (-not $CAAnswers) { $CAAnswers = [pscustomobject]@{} }

    $plan = Get-CACrlSharePlan -CAAnswers $CAAnswers
    Show-CACrlSharePlan -Plan $plan
    Write-Host ""

    if (-not $plan.Applicable) {
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    if (Read-CAConfirm -Prompt "Create this share + AD group?") {
        New-CACrlShare -Plan $plan
    }
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}
