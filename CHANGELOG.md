# Changelog

All notable changes to NSP.PKI are documented here. Versions follow
[SemVer](https://semver.org/). `0.x` until it has real use outside NSP.

## 0.1.2

- The hand-back folder now opens in Explorer for real. Explorer runs as the desktop user without
  elevation and refused to open the Administrators-only folder directly (seen live); the tool now
  gives that user read-only access to the one Responses folder first (what Explorer's own "Continue"
  prompt does, but read-only), then opens it. The user is the owner of the session's explorer.exe,
  so over-the-shoulder elevation works too.

## 0.1.1

- Menu 13 (hand-off) opens the output folder in Explorer after writing <Company>_PKI_Response.json,
  so the tech can copy it off the server (accept the access prompt - the folder is
  Administrators-only).

## 0.1.0

First release: the zip-era CA-Manager (NSP-FGTIPSecTools 1.1.0) as a module - PKI Manager dashboard,
launcher, NSP.Toolkit hand-off for menu 13, work-folder answers.

The other NSP modules it needs are installed from the PowerShell Gallery the first time they're needed,
so `Install-Module` of this one module is enough. Set `NSP_NO_AUTOINSTALL=1` to turn that off.
