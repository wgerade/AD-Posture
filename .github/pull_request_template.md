## Summary

- 

## Type of Change

- [ ] Bug fix
- [ ] New posture rule or scoring change
- [ ] Dashboard / UX change
- [ ] Documentation only
- [ ] Security hardening

## Validation

- [ ] `.\scripts\Invoke-ProjectChecks.ps1`
- [ ] Dashboard manually reviewed when UI changed
- [ ] README / CHANGELOG updated when user-visible behavior changed
- [ ] Synthetic sample data used for screenshots or demos

## Security

- [ ] No real AD report data, SIDs, DNs, usernames, or domain names committed
- [ ] No generated `data\` or `reports\` artifacts committed
- [ ] No local `config\ApprovedExceptions.json` committed
- [ ] No private keys, certificates, vaults, or credentials committed
- [ ] Remediation behavior remains `-WhatIf` or review-first by default

## Posture Impact

- [ ] Score semantics are documented when score behavior changes
- [ ] Finding output remains explainable for operations and executive views
- [ ] Native AD identities and approved exceptions are handled separately from correctable findings
