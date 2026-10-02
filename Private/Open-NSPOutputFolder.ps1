function Open-NSPOutputFolder {
    # Opens Explorer on the folder a hand-back file was written to, so the tech can copy it off the
    # server. Skipped without explorer.exe (Server Core), when nothing was written (dry run), and with
    # NSP_NO_EXPLORER=1 (the test runners set it).
    #
    # Explorer runs as the desktop user WITHOUT elevation, and opened straight onto an
    # Administrators-only folder it refuses outright - its "Continue" (gain access) prompt only
    # appears when you browse there yourself (confirmed live at a client, 2026-10-02). So first give
    # the desktop user read access to this one folder - what that prompt does, but read-only - then
    # open it.
    param([string]$Path)
    if (-not $Path -or $env:NSP_NO_EXPLORER -eq '1') { return }
    $folder = if (Test-Path -LiteralPath $Path -PathType Leaf) { Split-Path -Parent $Path } else { $Path }
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) { return }
    if (-not (Get-Command explorer.exe -ErrorAction SilentlyContinue)) { return }
    $sid = Get-NSPDesktopUserSid
    if ($sid) { Grant-NSPFolderRead -Path $folder -Sid $sid }
    Start-Process -FilePath explorer.exe -ArgumentList "`"$folder`""
}

function Get-NSPDesktopUserSid {
    # The account Explorer runs as in this session - the owner of this session's explorer.exe. That
    # is not always the account this (elevated) process runs as: over-the-shoulder elevation runs
    # the tool as a different admin. Falls back to this process's own account.
    $sessionId = (Get-Process -Id $PID).SessionId
    try {
        $shell = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop |
            Where-Object { $_.SessionId -eq $sessionId } | Select-Object -First 1
        if ($shell) {
            $owner = Invoke-CimMethod -InputObject $shell -MethodName GetOwnerSid -ErrorAction Stop
            if ($owner.Sid) { return [string]$owner.Sid }
        }
    } catch { Write-Verbose "explorer.exe owner lookup failed: $($_.Exception.Message)" }
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Grant-NSPFolderRead {
    # Adds one read-only ACE for -Sid on -Path (inherited by its files). A failure is a warning, never
    # an error - the tech can still browse there and accept Explorer's own prompt.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Sid)
    try {
        $identity = New-Object Security.Principal.SecurityIdentifier($Sid)
        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'ReadAndExecute', $inherit, 'None', 'Allow')
        # The access list only: Get-Acl/Set-Acl round-trip the audit list too, which needs
        # SeSecurityPrivilege (not enabled even in an elevated session).
        $dir = New-Object IO.DirectoryInfo($Path)
        $sections = [Security.AccessControl.AccessControlSections]::Access
        if ($PSVersionTable.PSEdition -eq 'Core') {
            $acl = [IO.FileSystemAclExtensions]::GetAccessControl($dir, $sections)
            $acl.AddAccessRule($rule)
            [IO.FileSystemAclExtensions]::SetAccessControl($dir, $acl)
        } else {
            $acl = $dir.GetAccessControl($sections)
            $acl.AddAccessRule($rule)
            $dir.SetAccessControl($acl)
        }
    } catch {
        Write-Warning "Could not give the desktop user read access to ${Path}: $($_.Exception.Message). Browse to it in Explorer and accept the access prompt."
    }
}
