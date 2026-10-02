# NSP.PKI

Active Directory Certificate Services for NSP VPN deployments, plus the **PKI Manager** dashboard
(formerly the zip-delivered CA-Manager in NSP-FGTIPSecTools). Windows PowerShell **5.1** compatible
(and 7+); imports on a bare host. NSP.Toolkit / NSP.Console / NSP.Bootstrap are loaded when the
dashboard starts.

## Start it

```powershell
Start-NSPPkiManager                       # the dashboard (relaunches elevated; starts in DRY RUN)
Start-NSPToolkit -Tool PKI                # same, via the NSP.Toolkit launcher
New-NSPPkiShim -ClientAnswers .\EXAMPLE.json -Path C:\Temp\PKI-Manager.ps1   # a launcher for the issuing CA
```

## What's in it

| Function | Purpose |
|---|---|
| `Start-NSPPkiManager` | The dashboard - same menus as the zip-era CA-Manager: RSAT, CA install, TameMyCerts, templates and permissions, App Proxy connector and Entra apps, CRL share, AIA/CDP/OCSP routing, OCSP, health check, test-certificate suite, renewal test, hand-back (menu 13), inventory, the enrollment gate, ad-hoc templates, vendor certificate batches. |
| `New-NSPPkiShim` | Write a launcher (NSP.ClientScripts ToolShim recipe) carrying a client's CA answers; the launcher blanks them from itself once handed over. |
| `ConvertTo-NSPPkiAnswers` | One ClientAnswers object -> the answers PKI Manager reads (the fields the Orchestrator's CA staging carried). |
| `Get-NSPPkiStatus` | Read-only snapshot of the CA (the dashboard's status header). |
| `Invoke-NSPPkiInventory` | The full read-only CA inventory report (menu 14). |

## What changed from the zip-era tool

- Answers live in `%ProgramData%\NSP\Toolkit\PKI\Answers\Answers.json` (Administrators and SYSTEM
  only), not `CAAnswers.json` next to the script. A `-CAConfigName` is saved there too
  (`PKICAConfigName`) - the zip-era launcher's `$CAServerName`.
- Menu 13 writes `<Company>_PKI_Response.json`, an NSP.Toolkit hand-off (shared header around the
  same Schema 4 payload; the FortiGate PFX and its password are still embedded), into the work
  folder's `Responses\` by default. Copy it to the Orchestrator's `Staging\<Abbrev>\Inbox\`.
  Re-running menu 13 still offers to reuse the FortiGate certificate from the last hand-back - from
  the new file or a zip-era `<stem>_CAResponse.json`.
- **R** relaunches the module in a new elevated window; **U** installs a newer NSP.PKI from the
  PowerShell Gallery and relaunches (the zip-era U re-ran the shim to fetch a newer zip).
- The first start on a server offers to move the zip-era tool's files (`CAStaging\`, old launchers
  with answers embedded) into the work folder (`Move-NSPToolLegacyData`).

## Source layout

- `Private\CA*.ps1` - the engine files, moved verbatim with small marked edits (`NSP.PKI:` comments).
  Several functions per file and not linted yet (`tools\AnalyzerBaseline.txt`); splitting them one
  function per file, and promoting reusable engine functions to `Verb-NSPPki*` public names, comes next.
- `Private\Engine\` - `DryRunEngine.ps1` (`Invoke-CAStep` / DRY RUN) and `Request-VPNCertCore.ps1`
  (certificate request/issue/revoke), copied from NSP-FGTIPSecTools' shared engines. Not loaded by
  the module loader; the CA files dot-source them.
- `Scripts\` - stand-alone scripts that ship with the module: `Get-CAManagerInventory.ps1` (menu 14),
  `Get-CAManagerEntraProxyInventory.ps1`, `Remove-CAAppProxySetup.ps1`, and `VPNCertEval\` (client-side
  VPN certificate evaluation - see its README).

## Tests

```powershell
.\tools\Test-Repo.ps1      # PSScriptAnalyzer + Pester 5 under Windows PowerShell 5.1 and pwsh
```

`Tests\Legacy\*.LegacyTest.ps1` are NSP-FGTIPSecTools' CA-Manager and VPNCertEval tests (its
AST-extraction harness), re-pointed at this module's files and run by `Tests\Legacy.Tests.ps1`.
Checks that only made sense for the zip (the build script, the Request-VPNCert wrapper, the shim's
update key) stay in NSP-FGTIPSecTools; the dashboard-wiring checks were updated for the module
(marked `NSP.PKI:`).
