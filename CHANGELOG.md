# Changelog

All notable changes to this project are documented here.

## [1.2.0] - 2026-06-05

### Added

- Static/offline first-release governance increment with snapshot schema `1.3`.
- Safe Action Plan playbooks for Sensitive Groups, ACL, GPO, ADCS, DNS, Trust, Kerberos/Auth, and Identity Risk.
- Orphaned sensitive-group findings integrated into score, Object Risk, Action Plan, Executive payloads, exceptions, and exports.
- Governed framework crosswalk catalog for NIST CSF, ISO 27001, SOC 2, and CIS Controls.
- Local artifact retention inventory/removal command with 180-day default, dry-run default, path protection, and removal log.
- Synthetic scale/precision validation script.
- Manual sidebar collapse and canonical `dashboard\trusts.html` page with `dashboard\trust.html` compatibility entry.
- Redaction coverage for raw SDDL/security descriptor fields when sensitive ACL evidence redaction is requested.

### Changed

- Dashboard/remediation documentation now separates first-release scope from deferred Platform Evolution work.
- Project validation baseline is now 180 Pester tests plus project checks and JavaScript syntax validation.

## [1.1.0] - 2026-05-22

### Added

- Opt-in ACL posture preview with dangerous ACE normalization for GenericAll, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights, ResetPassword, DCSync, membership/SPN writes, delete rights, legacy Microsoft LAPS, Windows LAPS, secret attributes, and unexpected object owners.
- ACL evidence and relationships in the Object Risk Explorer model when `Invoke-ADPostureAudit -IncludeAclPosture` is used.
- Local API endpoints for ACL finding queues and detail lookups, with right, severity, tag, trustee, target, and inheritance filters.
- Static ACL dashboard page for local review of dangerous rights, trustee/target exposure, inheritance, tags, and remediation focus.
- GitHub readiness script to validate required repository files, README coverage, module manifest health, documentation assets, ignore rules, and tracked sensitive artifacts when Git is available.
- Architecture and roadmap documentation for future identity risk, ACL, GPO, trust, OS hardening, database, service, authenticated UI, encrypted storage, and redacted export work.
- Demo asset generator that refreshes dashboard screenshots and GIF from synthetic data for safe public README publishing.
- Automatic Tier 0 / Tier 1 / Tier 2 privilege classification using `config/TieringModel.json`.
- Tier fields in findings, group summaries, dashboard payloads, and Operations dashboard filters.
- Operations dashboard insight charts for tiering, remediation effort, account type mix, and top group exposure.
- Cumulative, unbounded scoring model where overall score is the sum of active finding scores.
- Pester test suite for UAC labels, risk scoring, dashboard payload filtering, pipeline binding, and tiering.
- PSScriptAnalyzer settings and `scripts/Invoke-ProjectChecks.ps1`.
- GitHub Actions CI for linting and tests.
- GitHub-ready project docs and structure: license, contributing guide, security policy, editor settings, issue templates, screenshots, and demo GIF references.
- Approved baseline exceptions with owner, approver, ticket, reason, and expiry metadata.
- Per-finding score explanations with formula, score components, technical risk, and ATT&CK mappings.
- Readiness scorecard for Tier 0 exposure, high priority findings, UAC hygiene, stale identities, nested access paths, and expired approvals.
- Native identity metadata to distinguish customer-managed identities from built-in and architecture-managed AD principals.
- Dedicated Exceptions dashboard page for approved exceptions and native/monitoring identities.
- Account and action grouping views in the Operations dashboard.
- Operations access-path queue with a sticky score column and expandable per-row technical details.
- Exceptions governance KPIs for accepted exposure, approvals expiring soon, and missing owner/approver/ticket/reason metadata.
- Executive readiness controls and top remediation moves for meeting-ready scorecard reviews.
- Timeline exposure trend visualization.
- Security hardening helpers for PowerShell literals and AD filter literals.
- Sensitivity markers in snapshots and dashboard payloads.
- Dashboard Content Security Policy, no-referrer metadata, and visible sensitive-data handling banners.
- Tests covering remediation script input quoting.

### Changed

- CI now includes repository publication guardrails for generated sensitive artifacts.
- GitHub issue and pull request templates now include stronger security and posture-domain review checklists.
- `Invoke-ADPostureAudit` now accepts pipeline input from strings and common AD/domain-controller object properties.
- Risk scoring changed from capped dashboard-style score to open-ended cumulative exposure.
- Improved audit logging with `-Verbose` and optional `-LogPath`.
- Improved file write error handling with terminating errors.
- Operations dashboard separates fix impact, account exposure, group exposure, access paths, and remediation script UX.
- Dark dashboard theme improved for contrast, sticky headers, clearer controls, and responsive chart layouts.
- Operations dashboard now exposes score explanation, ATT&CK / technical risk, identity origin, and readiness controls.
- Operations dashboard now supports "why this matters", clickable score drill-down, correctable/native scope filtering, and broader search across SID, DN, CN, SamAccountName, type, tier, UAC, ATT&CK, and actions.
- Executive dashboard now has a print/save-PDF export flow for meeting-ready reports.
- `Open-ADPostureDashboard` now supports the dedicated Exceptions view and warns before opening sensitive dashboard data.
- CI workflow now runs with read-only repository permissions.

### Fixed

- Corrected UAC bonus decimal rounding in Windows PowerShell by using floating-point comparison.
- Normalized UAC labels into friendly comma-separated display values.
- Recognized `ms-DS-Group-Managed-Service-Account` and `ms-DS-Managed-Service-Account` as service account types instead of `Unknown`.
- Excluded `NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS` / SID `S-1-5-9` as a native AD authority principal.
- Hardened generated remediation scripts against quote breakout in member, group, and server values.

## [1.0.0] - 2026-05-21

### Added

- Initial AD sensitive group audit module.
- Nested membership resolution.
- Initial bounded risk score.
- CSV/JSON exports.
- Operations, Timeline, and Executive dashboards.
- Remediation command generation.
