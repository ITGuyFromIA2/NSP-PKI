# VPN Certificate Evaluation Harness

Steps through the PFX test suite that **CA-Manager menu 8** (`New-CATestCertSuite`) produces and,
for each cert, records:

1. whether FortiClient can bring up the tunnel with it, and what the account can reach ("rights");
2. an offline CRL / OCSP verdict from `certutil -verify -urlfetch`;
3. a pass/fail vs. the expected outcome (valid -> connects + full scope; revoked -> IKE rejected).

Run it on a **test box** that has FortiClient installed and the client's VPN profile configured.

---

## Files

| File | Role |
|---|---|
| `Build-VPNCertEvalTargets.ps1` | `ClientAnswers\<Abbrev>.json` -> **starter** `<Company>_EvalTargets.psd1` (endpoints + expected Allow/Block per group). Review before use. |
| `Invoke-VPNCertEval.ps1` | The runner. Import -> guided connect -> reachability -> disconnect -> `certutil` -> report. |
| `VPNCertEval.Common.ps1` | Shared probes / parsers (dot-sourced by both). |

---

## Workflow

### 1. Build the targets file

```powershell
.\Build-VPNCertEvalTargets.ps1 `
    -AnswersPath '..\..\..\..\IPSEC AIO\ClientAnswers\ACME.json' `
    -UnitTestsPath '..\..\..\..\Examples_Sources\User-UnitTests (3).ps1'   # optional merge
```

Produces `ACME_EvalTargets.psd1` next to the answers file. It is **a starter** - open it and:

* replace every `Host = 'RESOLVE-ME'` / `'CHANGE-ME-*'` and any `Notes = 'TODO ...'`;
* sanity-check each endpoint's `Services[]` (the port set is inferred from the service-group *name*);
* trim / extend each group's `CrossCheckBlocked[]` (endpoints that group should be **denied**);
* add vendor hosts / subnet sample hosts the answers file can't know about.

Derivation from the answers:

| Answers field | Becomes |
|---|---|
| `IKEv2_DCMembers` | `Universal[]` DC endpoints (DNS/Kerberos/LDAP/LDAPS/GC/RPC) |
| `RadiusGroupPairs[]` | one `Groups[]` bucket per label |
| `CustomAppRules[].AddressMembers` | `Allow` endpoints on the matching group (by `UserGroupName`) |
| `CustomAppRules[].ServiceNames` | inferred catalogue services (best effort) |
| `IKEv2_RDSMembers` / `IKEv2_FileServerMembers` | attached to internal/corp-looking groups |
| other groups' Allow targets | this group's `CrossCheckBlocked[]` |

### 2. Copy the PFX suite to the test box

Everything CA-Manager menu 8 wrote: the `*.pfx` files **and** the
`<Company>_CertTestSuite_<ts>.txt` summary (optional but recommended - it carries the
authoritative serial / thumbprint / revoked flag).

### 3. Run the evaluation

```powershell
.\Invoke-VPNCertEval.ps1 `
    -PfxDir      C:\Admin\TestPFX `
    -TargetsPath C:\Admin\TestPFX\ACME_EvalTargets.psd1 `
    -SummaryPath C:\Admin\TestPFX\ACME_CertTestSuite_20260909_101500.txt
```

For each PFX the harness:

1. imports it to `Cert:\CurrentUser\My` (`-CertStore LocalMachine` to use the machine store);
2. prints the cert + the expected outcome;
3. **waits for you to connect FortiClient with that cert and clear MFA** - then auto-detects the
   tunnel by pinging the marker host (first `Universal` endpoint, or `-MarkerHost`);
4. if up: probes `Universal` + the group's `Endpoints` + `CrossCheckBlocked`, and scores
   Allow-reachable / Block-denied / **leaks**;
5. **waits for you to disconnect**, confirms the tunnel dropped;
6. exports the public cert and runs `certutil -f -urlfetch -verify` -> `Good` / `Revoked` / `Undetermined`;
7. removes the imported cert (`-KeepCerts` to leave it).

### Why the connect step is manual

FortiClient's IPsec/IKEv2 tunnel has no reliable supported command line, and **MFA is interactive
on every connect** - a script can't answer an Azure MFA push or a token prompt. So you click
Connect / pick the cert / clear MFA; the harness does everything else. `-AttemptCliConnect` will
best-effort launch `FortiClient.exe` first, then still wait for you.

For the revoked certs it's quick: the FortiGate rejects them at IKE phase 1 *before* MFA - click
Connect, watch it fail, press `F`.

---

## Output (in `<PfxDir>\EvalResults\` unless `-OutDir`)

* `<Company>_CertEval_<ts>.txt` - summary table + per-endpoint reachability + totals (always).
* `<Company>_CertEval_<ts>.json` - full structured dump (always).
* `<Company>_CertEval_<ts>.xlsx` - Summary + Reachability sheets, green/red conditional
  formatting (only if the `ImportExcel` module is installed).
* `<stem>.cer` + `<stem>_certutil.txt` per cert - the exported public cert and raw verify output.

### Outcome scoring

| Cert | PASS | FAIL | WARN |
|---|---|---|---|
| valid | connected + `certutil` Good + rights match | did not connect | rights mismatch, or `certutil` not Good |
| revoked | not connected + `certutil` Revoked | **connected** (revocation not enforced) | not connected but `certutil` couldn't confirm Revoked |

A revoked cert that still connects usually means the FortiGate's CRL/OCSP cache hasn't turned over -
see the cache-refresh commands in the CA-Manager menu-8 summary file.

---

## Parameters worth knowing

| Param | Default | Notes |
|---|---|---|
| `-MarkerHost` | first `Universal` endpoint | address reachable **only** over the tunnel; the up/down signal |
| `-CertStore` | `CurrentUser` | `LocalMachine` needs an elevated shell |
| `-SkipConnect` | off | cert import + `certutil` only (fast revocation-only pass) |
| `-AttemptCliConnect` | off | best-effort `FortiClient.exe` launch before the manual wait |
| `-KeepCerts` | off | don't remove imported certs afterwards |
| `-TcpTimeoutMs` / `-PingTimeoutMs` | 500 | raise on a slow tunnel to cut false negatives |
