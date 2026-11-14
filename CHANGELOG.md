# Changelog

All notable changes to NSP.PKI are documented here. Versions follow
[SemVer](https://semver.org/). `0.x` until it has real use outside NSP.

## Unreleased

- New: `Get-NSPPkiCAKeyReport`, a read-only report of which key a CA is using. It gives the SHA-256 fingerprint of the CA certificate's public key (the same value `openssl pkey -pubin -outform DER | openssl dgst -sha256` gives), the key algorithm and size, and the key provider the CA is configured with. Record the fingerprint when a CA is created; compare it after a restore, a migration or a renewal that was meant to keep the key. It works on the local CA, a certificate object or a certificate file, returns a `Status` instead of throwing on a machine with no CA, and never opens, exports or changes a private key.
- Tests: `Invoke-CAInstall` and `Set-CAPublicationUrls` now have tests with every outside call replaced: nothing runs in a dry run, the steps run in order, the installer is given only the plan (never an existing key or a certificate file), and a failed step stops the ones after it. No behaviour changed.

## 0.1.4

- Release routine: `tools\Publish-ToGallery.ps1` now runs `Publish-NSPModule` from NSP.RepoTools, the checks every NSP module shares (including a client-reference sweep of the Git history). No change to the module itself.
- Tests: the ported hand-off test pins the stand-alone path, so an installed NSP.Toolkit no longer changes its result under Windows PowerShell 5.1.

## 0.1.3

- **The FortiGate PFX password is no longer in the hand-back (response Schema 5).** With the PFX and
  its password in one file, whoever had the file had the FortiGate's private key. Menu 13 shows the
  password once, copies it to the clipboard, and keeps a DPAPI-protected copy on the CA server for a
  re-run (asked for when another account re-runs). Schema 1-4 hand-backs are still read.
- **The CSR is the default** for the FortiGate identity certificate: menu 13 asks C (CSR from the
  FortiGate, recommended), I (an issued cert) or G (generate a PFX here), shows where to make the CSR
  on the FortiGate, and picks the file with a file dialog (NSP.Console 0.1.3 `Read-NSPFilePath`) or
  a pasted path - Windows blocks drag-and-drop onto the elevated console.
- VPNCertEval only reads data: `ConvertFrom-UnitTestsFile` refuses anything but plain literals before
  evaluating them, and `Read-EvalTargets` no longer has an `Invoke-Expression` fallback. Site-specific
  application names that mean "reached over RDP" moved out of the script into an optional local map
  (`VPNCertEval.LocalMap.psd1` or `NSP_VPNCERTEVAL_MAP`).
- Client-derived names in tests and comments replaced with neutral ones; the health check's fallback
  template is `IKEv2VPNInternalUsers` (the module's real default), not the old `IKEv2VPNCorpLAN`.
- Needs NSP.Console 0.1.3 and NSP.Toolkit 0.1.1. The sibling loader announces Gallery installs and is
  generated from NSP-Toolkit's canonical copy; the module loader dot-sources files in name order.

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
