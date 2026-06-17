# Pester 5 Migration

> **Status: executed in 1.3.0.** All test files were converted to Pester 5 operator syntax with file-level setup wrapped in `BeforeAll`; CI pins Pester 5.7.1 and `scripts/Invoke-ProjectChecks.ps1` requires Pester 5+. The original plan below is kept as the record of scope and rationale.

## Why migrate

- Pester 4 is in maintenance mode; Pester 5 is the supported line.
- Pester 5 ships with newer PowerShell images and is the default on most contributor machines.
- Discovery-phase isolation catches accidental file-load side effects that Pester 4 hides.

## Required changes

1. **Assertion operator syntax** (largest, mechanical): `Should Be` / `Should Match` / `Should Not Be` / `Should BeNullOrEmpty` / `Should Throw` become `Should -Be`, `Should -Match`, `Should -Not -Be`, `Should -BeNullOrEmpty`, `Should -Throw`. Every test file is affected.
2. **Discovery vs. run phase**: Pester 5 executes `Describe`/`It` bodies in a separate run phase. Code at file top level (dot-sourcing `src` files, defining stub functions such as `Get-ADGroup`, seeding `$script:` state) still runs during discovery, but variables consumed inside `It` blocks must be defined in `BeforeAll`/`BeforeEach` or passed via `-TestCases`. Each test file needs review:
   - Move dot-sourcing and stub function definitions into `BeforeAll`.
   - Move per-test state resets (for example `Reset-LookupState` in `SensitiveGroupLookup.Tests.ps1`) into `BeforeEach`.
3. **`$TestDrive` usage** keeps working, but references inside `Describe` bodies outside `It`/`Before*` blocks must move.
4. **CI workflow**: change `Save-Module Pester -RequiredVersion 4.10.1` to the chosen 5.x version and keep `Invoke-Pester` invocation through `Invoke-ProjectChecks.ps1` (already version-aware).
5. **`Invoke-ProjectChecks.ps1`**: flip the preference order so Pester 5 is selected when present (currently prefers 4).

## Suggested execution order

1. Pick a pinned version (5.7.x at the time of writing) and update CI plus `Invoke-ProjectChecks.ps1`.
2. Migrate one small file end to end (`Uac.Tests.ps1`) to validate the `BeforeAll` pattern for dot-sourcing and stubs.
3. Apply the mechanical `Should` operator conversion across the suite (regex-assisted, then manual review).
4. Move file-level stubs/state into `BeforeAll`/`BeforeEach` file by file, running each file as it is converted.
5. Run the full suite plus `scripts/Invoke-ProjectChecks.ps1` and compare test counts against the Pester 4 baseline (must remain >= the current count, all passing).

## Risks

- Pester 5 discovery executes top-level code twice in some flows; tests that mutate global state at file scope can behave differently. The current suite's pattern of defining stub functions at file scope generally keeps working because function definitions persist, but `$script:` state initialization must be reviewed.
- `-PassThru` result object shape changed; any tooling reading `FailedCount` keeps working, but custom result parsing must be checked.
