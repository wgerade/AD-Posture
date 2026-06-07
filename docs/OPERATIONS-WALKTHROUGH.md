# Operations Walkthrough

This is the v1 demo and recording script. Use synthetic or sanitized lab data only. Do not record real SIDs, DNs, account names, tickets, CSV/JSON payloads, remediation scripts, or internal paths.

## Refresh Demo Assets

Regenerate all public screenshots, sanitized PowerShell prints, and the README GIF:

```powershell
.\scripts\New-DemoDashboardAssets.ps1
```

The generator writes synthetic `corp.example` dashboard payloads, captures dashboard screenshots with Microsoft Edge, creates sanitized PowerShell operation prints, updates the checked-in PNG files under `docs\assets` plus `docs\assets\demo.gif`, and leaves generated dashboard payloads ignored by git. Edge is used only as a headless screenshot renderer for demo assets; it is not required to run the audit, export reports, or operate the static dashboard. Remove `dashboard\dashboard-data.js`, `dashboard\latest-dashboard.json`, `dashboard\timeline-data.js`, `dashboard\timeline-comparison.json`, and `.tmp-demo-assets` after capture if they remain.

## Current Visual Assets

| Asset | Purpose |
| --- | --- |
| `docs\assets\operations-dashboard.png` | Operations and Action Plan landing page |
| `docs\assets\objects-dashboard.png` | Object Risk evidence and relationships |
| `docs\assets\auth-dashboard.png` | Kerberos/Auth posture |
| `docs\assets\acl-dashboard.png` | ACL posture evidence |
| `docs\assets\gpo-dashboard.png` | GPO posture evidence |
| `docs\assets\adcs-dashboard.png` | ADCS posture evidence |
| `docs\assets\trust-dashboard.png` | Trust posture |
| `docs\assets\dns-dashboard.png` | DNS posture |
| `docs\assets\exceptions-dashboard.png` | Exception governance |
| `docs\assets\timeline-dashboard.png` | Drift and timeline review |
| `docs\assets\executive-dashboard.png` | Executive narrative |
| `docs\assets\powershell-import.png` | Module import and public command check |
| `docs\assets\powershell-focused-audit.png` | Safe focused audit command |
| `docs\assets\powershell-planned-full.png` | Planned broad audit with pacing |
| `docs\assets\powershell-open-dashboard.png` | Static dashboard launch |
| `docs\assets\powershell-retention-dry-run.png` | Retention inventory dry run |
| `docs\assets\demo.gif` | Short README motion demo |

## Safe Operator Flow

1. Use a hardened management workstation or jump server with RSAT. Do not use an interactive Domain Controller session as the normal operating model.

2. Import the module:

```powershell
Import-Module .\ADPosture.psd1 -Force
Get-Command -Module ADPosture
```

3. Run a focused read-only audit first:

```powershell
Invoke-ADPostureAudit `
  -IncludeOptionalGroups `
  -IncludeKerberosAuthPosture `
  -IncludeTrustPosture `
  -IncludeDnsPosture `
  -LogPath .\reports\audit.log
```

4. Add heavier collectors only after approval:

```powershell
Invoke-ADPostureAudit `
  -IncludeAclPosture `
  -IncludeAclAllObjects `
  -IncludeGpoPosture `
  -IncludeGpoSysvolAcl `
  -IncludeAdcsPosture `
  -AclReadDelayMilliseconds 100 `
  -LogPath .\reports\audit-full.log
```

5. Open the static dashboard:

```powershell
Open-ADPostureDashboard
Open-ADPostureDashboard -View ObjectRisk
Open-ADPostureDashboard -View Executive
```

6. Inventory local artifacts before cleanup:

```powershell
Invoke-ADPostureArtifactRetention -RootPath . -RetentionDays 180
```

7. Remove old artifacts only with explicit approval:

```powershell
Invoke-ADPostureArtifactRetention -RootPath . -RetentionDays 180 -Remove
```

## EDR And Defender Coordination

Do not request broad bypasses. Register the run through normal change governance:

- Approved operator identity and management host.
- Tool directory and expected PowerShell module path.
- Expected output paths under `reports\` and `data\`.
- Hashes or signing metadata when available.
- Expected PowerShell, LDAP, SYSVOL, DNS, and PKI read activity.
- Retention owner and removal process for generated artifacts.

## Video Script

Target 5 to 8 minutes.

1. Show scope: offline/static AD posture, read-only collectors, no backend platform, no real-time alerting.
2. Show requirements: Windows, RSAT, PowerShell 5.1+, AD read visibility, controlled management server.
3. Show `powershell-import.png`: import module and public commands.
4. Show `powershell-focused-audit.png`: focused audit first.
5. Show `powershell-planned-full.png`: broad audit only with approval and pacing.
6. Open Operations and explain exposure score, readiness, Action Plan, exceptions, and first fix.
7. Open Objects and explain object evidence, relationships, and native/default AD exclusions.
8. Open Auth/Kerberos, ACL, GPO, ADCS, Trust, and DNS. For each page, show imports, filters, selected row profile, and remediation guidance.
9. Open Exceptions and show active/expired approvals.
10. Open Timeline and explain drift after at least two snapshots.
11. Open Executive and use `Print / Save PDF`.
12. Show `powershell-retention-dry-run.png`: retention inventory first; destructive cleanup requires `-Remove` and explicit approval.

## Pre-Recording Checklist

- Regenerate demo assets with `.\scripts\New-DemoDashboardAssets.ps1`.
- Confirm `git status --short --ignored` shows no tracked generated payloads.
- Confirm no tracked sensitive artifacts with `git ls-files`.
- Confirm public docs do not mention internal lab domains or private lab scripts.
- Open every dashboard menu from the generated synthetic payload before recording.
- Use only `corp.example` / `contoso.local` style synthetic names in narration.

## Safety Notes

- The v1 score is an internal exposure index, not a market benchmark or compliance certification.
- `lastLogonTimestamp` is replicated and approximate; stale findings require operational validation.
- Playbooks generate review guidance and `WhatIf` scripts where deterministic. They do not execute changes automatically.
