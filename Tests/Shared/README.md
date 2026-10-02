# Tests\Shared\

**`TestAssertions.ps1` is the canonical copy** of the NSP "AST-extract one function + queued
Read-Host mock + manual assertion counter" harness. It was first written ad hoc in
`NSP-FGTIPSecTools`, promoted here so every NSP repo references one copy instead of forking it.

## When to use this vs. Pester

- **Pester 5** is the default for anything that is a real module with a manifest and an exported
  surface (like NSP.Bootstrap itself). Use `Describe`/`It`/`Should -Be`.
- **This harness** is for testing a single function that lives inside a large script with real
  load-time side effects (Read-Host prompts, self-elevation, file writes) - the FortiGate CLI
  Builder, the Master Orchestrator, the superscript modules. `Get-FunctionSource` pulls one
  function out via the parser without executing the rest of the file. Pester can't do that on
  its own; you can call `Get-FunctionSource` from inside a Pester `BeforeAll` and get both.

Keep this file in sync by copying, not editing per-repo. If it needs a change, change it here
and re-copy outward.
