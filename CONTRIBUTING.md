# Contributing

Thanks for helping improve AD Posture.

## Development Setup

Requirements:

- Windows PowerShell 5.1 or PowerShell 7+
- Pester
- PSScriptAnalyzer
- ActiveDirectory module only for real AD audit runs

Install test tooling:

```powershell
Install-Module Pester -Scope CurrentUser -Force
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
```

Run local checks:

```powershell
.\scripts\Invoke-ProjectChecks.ps1
```

## Pull Request Checklist

- Keep public cmdlet behavior backward compatible unless the change is explicitly breaking.
- Add or update Pester tests for scoring, tiering, dashboard payloads, or parsing changes.
- Update `CHANGELOG.md` for user-visible changes.
- Update `README.md` when commands, outputs, dashboards, or prerequisites change.
- Avoid committing real AD export data. Use anonymized examples only.

## Contribution License

By submitting a contribution, you agree that your contribution is provided under the same licensing model as the rest of the project:

- Code contributions are licensed under the PolyForm Noncommercial License 1.0.0.
- Documentation, screenshots, diagrams, and other non-code contributions are licensed under CC BY-NC-SA 4.0.

Do not submit code, images, text, or data that you do not have the right to contribute under these terms.

## Coding Guidelines

- Prefer PowerShell 5.1-compatible syntax.
- Use terminating errors (`-ErrorAction Stop`) where failures must be caught.
- Use `Write-Verbose`, `Write-Warning`, and `Write-ADPostureLog` for operator-visible diagnostics.
- Keep configuration in `config\*.json` when behavior needs to be organization-tunable.

## Security Notes

This project audits privileged Active Directory memberships. Do not include production domain names, user names, SIDs, DNs, or report exports in issues or pull requests unless they are anonymized.
