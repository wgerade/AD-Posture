# Governed Remediation, Crosswalks, and Artifacts

This project remains an offline/static Active Directory exposure audit. It complements MDI, SIEM, GRC, and EDR tooling; it does not provide real-time detection, alerting, continuous monitoring, or certified regulatory assessment.

## Safe Playbooks

The Action Plan centralizes remediation playbooks for Sensitive Groups, ACL, GPO, ADCS, and DNS findings.

- Playbooks never execute changes automatically.
- Deterministic scripts are generated only when the finding has enough proven evidence.
- DNS scripts use `-WhatIf` and re-query the record before removal.
- ACL, GPO, and ADCS playbooks remain blocked when trustee, target, setting, scope, rollback, or publication state is ambiguous.
- Sensitive-group membership removals continue to use `New-ADPostureRemediationScript`, which validates direct membership in the selected removal group before change.
- Orphaned sensitive groups are detected and scored, but deletion is never scripted automatically.

## Framework Crosswalks

Framework mappings are stored in `config/FrameworkCrosswalk.json`. They include framework name, control identifier, control name, domain or finding type scope, rationale, and catalog version.

The crosswalk is not a compliance certification, benchmark, or regulatory equivalence statement. Only findings with a defensible mapping receive framework metadata.

## Artifact Retention

`Invoke-ADPostureArtifactRetention` implements local retention governance:

- default retention: 180 days
- default mode: dry-run inventory
- deletion requires `-Remove`
- paths are resolved and protected so external paths are not removed
- `latest-*` files are preserved
- removal activity is logged under `reports`

## Scale And Precision Suite

`scripts/Test-ADPostureSyntheticScale.ps1` creates deterministic synthetic datasets and reports elapsed time, throughput, orphan-group accuracy, generated playbooks, and framework summary counts. Real validation across external AD environments remains an environmental dependency.
