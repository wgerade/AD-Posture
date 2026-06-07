# Architecture

AD Posture is a local PowerShell module, delivered as the ADPosture PowerShell module, with static HTML dashboards backed by an embedded report bundle.

## Current Shape

```text
ADPosture.psd1 / ADPosture.psm1
  src/Public/      Operator commands and report entry points
  src/Private/     AD resolution, scoring, enrichment, logging, dashboard data
  config/          Static catalogs and local governance inputs
  dashboard/       Static local HTML dashboards
  reports/         Generated exports, ignored by Git
  data/            Historical snapshots, ignored by Git
  tests/           Pester coverage for module behavior
  scripts/         Operator and CI utility scripts
```

The collector produces complete JSON/CSV artifacts and `dashboard-data.js`. `Open-ADPostureDashboard` opens the selected HTML file directly and refreshes the embedded bundle only when it is missing or older than `latest-dashboard.json`. Object Risk limits its rendered table to 100 rows per page while using the complete embedded data for KPIs and profiles.

## Security Boundaries

- AD data collection runs locally with the operator's current AD read permissions.
- Unattended scheduling is not recommended by default. Avoid `SYSTEM`, stored scheduled-task passwords, and default gMSA/sMSA scheduling patterns for this audit unless a separate risk review explicitly approves the identity model.
- Generated reports and dashboard payloads are sensitive and should be stored on encrypted, access-controlled storage.
- Opening a dashboard does not create a persistent service or background PowerShell process.
- Remediation output is review-ready script text and uses `-WhatIf` by default.
- Native AD principals and approved exceptions are separated from correctable operational findings.
- Public demos, screenshots, and issues must use synthetic data.

## Domain Modules

The codebase should grow by posture domain, not by dashboard page. Each domain should expose a collector, scoring model, normalization layer, tests, and dashboard payload contract.

Planned domains:

- Sensitive groups and privilege nesting.
- Identity risk from account attributes, authentication flags, age, activity, and ownership.
- Object Risk Explorer for object-level score summaries, evidence, relationships, and drill-down views across users, groups, computers, service accounts, OUs, GPOs, and sensitive containers.
- ACL posture for privileged rights over users, groups, OUs, GPOs, AdminSDHolder, and domain objects.
- GPO posture for risky settings, delegation, links, enforcement, WMI filters, and script usage.
- Trust posture for forest/domain trusts, SID filtering, selective authentication, and transitivity.
- Kerberos/Auth posture for roastable identities, weak encryption, delegation paths, RBCD, and privileged-account delegation protection gaps.
- DNS posture for AD-integrated zones/records, DnsAdmins, zone update/scavenging posture, DNS ACL delegation, wildcard/stale/dangling records, and privileged DNS delegation.
- Server baseline collection is future work and is not active in the v1 architecture.
- Operational hygiene for stale accounts, orphaned objects, unmanaged service accounts, and cleanup candidates.

## Deferred Architecture

Database, backend service, RBAC, API, and multiuser UI work are outside v1. The active architecture is the PowerShell collector, local artifacts, static dashboards, CSV/JSON exports, exception governance, and safe Action Plan playbooks.

## Extension Rules

- Keep raw AD collection separate from scoring and presentation.
- Add tests for every new domain scoring rule.
- Keep generated sensitive artifacts out of Git by default.
- Prefer additive dashboard payload fields to breaking current static dashboards.
- Make all remediation actions explainable, reviewable, and safe by default.
