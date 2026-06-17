# Current State

Last updated: 2026-06-11

This file is the short working memory for the project. Read it before continuing implementation work.

## Recent Changes (1.3.0)

- Sensitive groups resolve by well-known SID first (`Resolve-ADPostureSensitiveGroupIdentity`), with name lookup as fallback; localized/renamed built-ins are found.
- Membership resolution and account enrichment honor `-Server` through `-DomainParams`, and `Get-ADGroupMember` failures fall back to member-attribute enumeration (`MembershipEnumerationMode`).
- Membership approved exceptions require at least one membership scope field; unscoped entries warn and are ignored.
- Load-order override files (`*Safe`, `*Static`, `*FullHistory`) were merged into their canonical files and deleted.
- `ADPOSTURE_OUTPUT_ROOT` selects a writable output root for data/reports/dashboard/exceptions.
- Dashboards: `bootstrap.js` removed (static script tags), synthetic demo fallback via `demo-data.js`/`demo-timeline-data.js` with banner, JSON import validation, centered loading overlay, fixed-height scrolling tables, 300-row batched access-path rendering, readable playbook labels, no score donut, 12px font floor, encoding-safe sort arrows. `tour.js` is reserved for the public demo page and is not loaded by product pages.
- Snapshots and dashboard meta carry `AuditedBy` (operator identity) alongside domain/timestamp.
- `dashboard/dashboard-data.js` and `dashboard/timeline-data.js` are untracked again; the CI sensitive-artifact guard passes.
- Test suite migrated to Pester 5 (5.7.1 in CI and project checks); see `docs/PESTER5-MIGRATION.md`.
- Directory ACL reads (ACL collector, GPO security filtering, ADCS template/CA/NTAuth access) honor `-Server` through server-bound AD provider drives (`Get-ADPostureDirectoryAclPath.ps1`) with `LDAP://<server>/<dn>` fallback.

## Project Focus

AD Posture is evolving from a sensitive group audit tool into a broader Active Directory posture platform. The current implementation still keeps the static/offline dashboard workflow, JSON snapshots, and local read-only API as the main delivery path.

## Implemented Areas

- Sensitive group audit with nested membership resolution.
- Tier 0 / Tier 1 / Tier 2 classification from `config/TieringModel.json`.
- Cumulative object risk model with `objects`, `objectEvidence`, and `objectRelationships`.
- Object risk queue excludes native/default AD architecture objects from actionable scoring and from the object queue, including legacy payloads identified by well-known RID or built-in names.
- Object risk queue also suppresses broad ACL trustees such as `Everyone` and `Authenticated Users` as standalone remediation objects while preserving their evidence and relationships on the controlled target.
- Exceptions dashboard is reserved for approved business risk exceptions only; native/default architecture rows are not rendered there.
- Approved exceptions now cover sensitive group membership, ACL posture findings, GPO posture findings, and ADCS posture findings with scoped matching fields. Membership-only exception entries do not match ACL/GPO/ADCS rows.
- Static dashboards:
  - `dashboard/index.html`
  - `dashboard/objects.html`
  - `dashboard/adcs.html`
  - `dashboard/acl.html`
  - `dashboard/gpo.html`
  - `dashboard/exceptions.html`
  - `dashboard/timeline.html`
  - `dashboard/executive.html`
- Kerberos/Auth posture module for AS-REP roastable accounts, Kerberoastable service principals, weak Kerberos encryption, unconstrained/constrained delegation, RBCD, and privileged-account delegation protection gaps.
- Synthetic demo asset generator through `scripts/New-DemoDashboardAssets.ps1`.
- Pester coverage for current scoring, dashboard payload, object risk, ACL posture, GPO posture, and public release hygiene.

## Hygiene Thresholds

- `Invoke-ADPostureAudit -StaleDays <days>` controls when a user/service account with no usable logon is classified as stale. Default: `90`.
- `Invoke-ADPostureAudit -PasswordAgeDays <days>` controls when password age is called out in privileged-account remediation guidance. Default: `365`.
- `-PasswordAgeDays 0` disables password-age findings/recommendations for organizations that manage this through another process.
- These values are also exposed by `scripts/Invoke-ADPostureAudit.ps1` for operational runs.

## Full Audit Syntax

`Invoke-ADPostureAudit -Full` is the maximum v1 collection mode. It enables optional groups, full ACL posture including all objects, GPO posture with SYSVOL ACL review, ADCS, Kerberos/Auth, Trust, and DNS.

`-Full` does not combine with granular scope switches such as `-IncludeAclPosture` or `-IncludeDnsPosture`. Tuning parameters such as `-AclReadDelayMilliseconds` and `-AclEffectiveTrusteeLimit` remain available. Server baseline collection parameters are not part of the public v1 contract.

## ACL Posture State

ACL posture is opt-in through:

```powershell
Invoke-ADPostureAudit -IncludeAclPosture
```

Broad ACL scan with gentler pacing:

```powershell
Invoke-ADPostureAudit -IncludeAclPosture -IncludeAclAllObjects -AclReadDelayMilliseconds 25
```

Operational recommendation: do not start with full-domain `-IncludeAclAllObjects` on a primary DC or busy production environment. Prefer staged scans with `-AclSearchBase` per OU/subtree, run from a dedicated management/audit workstation, use a maintenance or low-traffic window, and start with conservative pacing such as `-AclReadDelayMilliseconds 100` or higher. Treat `-AclReadDelayMilliseconds 0` as synthetic-test only because broad ACL collection can act as a stress test for a VM, jump server, or domain controller.

After `ACL posture collection complete`, AD ACL reads are done. Any remaining delay is local CPU/memory work to classify raw ACEs into normalized ACL findings and object-risk evidence.
The collector now prints a final `ACL posture analysis complete` message after local ACL risk classification is finished.

Current collector scope:

- Domain root.
- `CN=AdminSDHolder,CN=System,...`.
- Sensitive groups already scanned by the sensitive-group audit.
- Optional explicit expansions:
  - Organizational Units with `-IncludeAclOrganizationalUnits`.
  - GPO containers with `-IncludeAclGpoContainers`.
  - AdminSDHolder-protected users with `-IncludeAclPrivilegedUsers`.
  - AdminSDHolder-protected computers with `-IncludeAclPrivilegedComputers`.
  - AdminSDHolder-protected groups with `-IncludeAclPrivilegedGroups`.
  - Users, groups, computers, OUs, and GPO containers under the domain naming context with `-IncludeAclAllObjects`.
  - Users, groups, computers, OUs, and GPO containers under selected distinguished names with `-AclSearchBase`.
- ACL targets are deduplicated by distinguished name before ACL reads.
- ACL findings carry `TargetPrivilegeTier` and `TargetRiskContext`; Tier 0 targets keep full score, while common-object findings are still reported with adjusted context-aware severity.
- ACL collection now emits console/log progress for target discovery, ACL reads, and post-collection ACL risk classification, including processed counts and final finding count.
- Broad ACL reads default to `-AclReadDelayMilliseconds 25` to reduce sustained pressure on a DC, VM host, or jump server in production-like environments. Passing `-AclReadDelayMilliseconds 0` is still allowed for disposable labs, but broad `-IncludeAclAllObjects` runs warn when no read delay is used.
- ACL trustee enrichment preserves the raw trustee string, attempts SID/DN/object-class resolution when AD lookup is available, keeps name-only trustees as named identities, and marks SID-only/deleted trustees with `UnresolvedTrustee`.
- ACL target enrichment preserves `TargetCanonicalName` when AD target discovery returns `CanonicalName`; ACL API search and the ACL dashboard can use it alongside DN/SID/name.
- ACL object evidence preserves ACE detail fields from ACL findings, including object type, inherited object type, inheritance type, object flags, inheritance flags, propagation flags, and access control type.
- Owner findings preserve explicit owner name, SID, DN, object class, and source descriptor details in ACL findings, object evidence, and the ACL dashboard profile.
- Snapshot comparison now includes ACL drift: `New`, `Missing`, `Changed`, and `Unchanged` ACL findings, plus timeline counts for new/removed/changed/unchanged ACL exposure.
- The ACL dashboard can filter by drift state and summarizes new critical/high ACL findings when comparison data is loaded.
- Dashboard payloads include ACL field classification metadata and support redacted ACL evidence export through `Get-ADPostureDashboardPayload -RedactSensitiveAclEvidence` and `Export-ADPostureReport -RedactSensitiveAclEvidence`.
- Effective ACL exposure v1 is modeled when group trustees can be expanded. Direct ACE evidence remains intact, effective trustees are represented separately, and relationship paths connect effective trustee -> direct ACL trustee -> target.
- Static ACL dashboard payloads keep all ACL findings but bound embedded effective-trustee expansion to a count plus sample so broad scans do not inflate `latest-dashboard.json` and `dashboard-data.js`. Complete effective-trustee expansion is exported in `reports\audit-*-acl-effective-trustees.csv` for cleanup workflows.
- ACL group trustee expansion is attempted by the collector with `Get-ADGroupMember -Recursive` and a default `AclEffectiveTrusteeLimit` of 100 members per direct group trustee. The public command exposes `-AclEffectiveTrusteeLimit` for tuning.
- Object Risk consolidates multi-attribute credential ACL findings such as Windows LAPS, legacy LAPS, and secret-attribute access by target + trustee + normalized right. The ACL queue remains granular per ACE/attribute, but the Objects page shows one exposure with aggregated attribute detail to avoid repeated evidence and relationship paths.
- Object Risk labels GPO ACL targets as `GPO: <name>` so a GPO named like a trustee, for example `Everyone`, is not confused with the `Everyone` broad principal.

Current normalized ACL findings:

- `GenericAll`
- `GenericWrite`
- `WriteDacl`
- `WriteOwner`
- `AllExtendedRights`
- `ResetPassword`
- `DCSync`
- `Delete`
- `WriteMembership`
- `WriteSPN`
- `WriteAccountControl`
- `LegacyLapsControl`
- `WindowsLapsControl`
- `SecretAttributeAccess`
- `ObjectOwner`

Current ACL evidence/tags include:

- `SensitiveAclTrustee`
- `SensitiveAclTarget`
- `DCSyncCapable`
- `Tier0Exposure`
- `MembershipControl`
- `KerberoastExposure`
- `LegacyLAPS`
- `LegacyLapsExposure`
- `WindowsLAPS`
- `WindowsLapsExposure`
- `CredentialExposure`
- `UnexpectedOwner`
- `OwnerControl`
- `DestructiveAcl`
- `UnresolvedTrustee`
- `EffectiveAclExposure`
- `EffectiveTrustee`

Owner handling:

- Unexpected non-built-in owners on sensitive targets generate `ObjectOwner` findings.
- Built-in/expected owners such as Domain Admins, Enterprise Admins, Administrators, SELF, SYSTEM, and Enterprise Domain Controllers are suppressed.
- Owner evidence uses `EvidenceType = SensitiveAclOwner`.
- Owner findings use the target DN as `SourceDescriptorId` when the collector did not provide a more specific descriptor id.

LAPS handling:

- Legacy Microsoft LAPS signals:
  - `ms-Mcs-AdmPwd`
  - `ms-Mcs-AdmPwdExpirationTime`
- Windows LAPS signals:
  - `msLAPS-PasswordExpirationTime`
  - `msLAPS-Password`
  - `msLAPS-EncryptedPassword`
  - `msLAPS-EncryptedPasswordHistory`
  - `msLAPS-EncryptedDSRMPassword`
  - `msLAPS-EncryptedDSRMPasswordHistory`
  - `msLAPS-CurrentPasswordVersion`
  - `ms-LAPS-Encrypted-Password-Attributes`
- The collector attempts to resolve LAPS schema GUIDs to attribute names when AD schema access is available.
- Clear-text LAPS password values must never be collected into normal report/dashboard payloads.
- LAPS ACL validation does not require Entra ID for AD DS scenarios; legacy LAPS and Windows LAPS can be validated against the local AD schema/ACLs.
- ACL finding reasons are attribute-specific for LAPS/secret attributes. For example, Windows LAPS password, encrypted password, encrypted password history, DSRM password, expiration time, and version metadata receive distinct explanations instead of a generic repeated reason.

## GPO Posture State

GPO posture is opt-in through:

```powershell
Invoke-ADPostureAudit -IncludeGpoPosture
```

Staged OU link discovery can be limited with:

```powershell
Invoke-ADPostureAudit -IncludeGpoPosture -GpoSearchBase 'OU=Servers,DC=contoso,DC=local'
```

Deeper GPO filesystem/script-path validation is opt-in:

```powershell
Invoke-ADPostureAudit -IncludeGpoPosture -IncludeGpoSysvolAcl
```

Current GPO posture scope:

- Reads GPO containers under `CN=Policies,CN=System,...`.
- Reads the domain root `gPLink`.
- Reads linked OU scopes under the domain naming context or selected `-GpoSearchBase` values.
- Parses `gPLink` options for disabled and enforced links.
- Reports missing or unusual GPO SYSVOL paths using metadata only.
- Keeps GPOs with all settings disabled, partial user/computer sections disabled, orphaned links, disabled links, script-extension metadata, and enforced links as context/inventory instead of standalone risk queue findings.
- Keeps `Gpos`, `GpoLinks`, and `GpoFindings` in snapshots/dashboard payloads so GPO evidence can be tied back to policy inventory and linked scopes.
- Correlates dangerous ACL findings on `groupPolicyContainer` objects with collected GPO links when `-IncludeAclPosture -IncludeAclGpoContainers -IncludeGpoPosture` are used together.
- Scores GPO delegated control by delegated right, scope criticality, link state, and trustee breadth. The same `GenericAll`/`Everyone` delegation is Critical on `OU=Domain Controllers,...` and lower on a general OU.
- Parses enforced links but does not generate standalone enforced-link findings by default. Enforced state is retained as contextual scoring data when another GPO risk, such as dangerous delegation, exists.
- With `-IncludeGpoSysvolAcl`, reads the GPO SYSVOL folder ACL, parses configured startup/shutdown/logon/logoff script metadata, scans standard GPO script folders, and checks ACLs on script files/folders that live inside the collected GPO SYSVOL tree. Script presence by itself is treated as context, not a risk finding. This can report broad write/full-control over policy files, script files, script folders, and external script paths. External file server paths are not contacted for ACL validation; they are reported as out-of-scope execution dependencies. DC-to-DC SYSVOL ACL drift comparison is outside the first-release static/offline scope.
- Also with `-IncludeGpoSysvolAcl`, parses `GptTmpl.inf` for high-risk security options/user rights and performs bounded script content review inside SYSVOL for hard-coded password-like literals, local Administrators modification, remote download/execute patterns, and endpoint protection/firewall disablement.
- Risky GPO script-content reasons describe the operational impact, not just the detected pattern. Empty script files are ignored and covered by tests.
- Reads GPO Apply Group Policy ACL entries as security-filtering context. Broad security filtering becomes a finding only for critical or infrastructure scopes; default `Authenticated Users` alone is not treated as a standalone risk finding.
- Reports WMI filter dependencies on critical or infrastructure-linked GPOs so operators can validate filter health, ownership, and expected target count.
- Detects user policy loopback processing from `Registry.pol` on critical or infrastructure scopes and reports the mode when it can be inferred.
- Reviews Group Policy Preferences XML under SYSVOL for credential/cpassword exposure, local Administrators changes, scheduled task execution, service control, and external executable/script paths. External paths are reported without attempting remote ACL validation.
- Renders GPO posture in `dashboard/gpo.html`.
- Exposes GPO findings through the static dashboard payload.

Current normalized GPO risk findings:

- `GpoMissingSysvolPath`
- `GpoUnusualSysvolPath`
- `GpoDelegationControl`
- `GpoSysvolAclWeak`
- `GpoSysvolAclUnvalidated`
- `GpoScriptFileAclWeak`
- `GpoScriptFolderAclWeak`
- `GpoExternalScriptPath`
- `GpoScriptMetadataUnparsed`
- `GpoBroadSecurityFiltering`
- `GpoRiskyUserRight`
- `GpoRiskySecurityOption`
- `GpoRiskyScriptContent`
- `GpoWmiFilterDependency`
- `GpoLoopbackProcessing`
- `GpoPreferenceCredential`
- `GpoPreferenceLocalAdmin`
- `GpoPreferenceScheduledTask`
- `GpoPreferenceServiceControl`
- `GpoPreferenceExternalPath`

Current GPO scope tags include:

- `DomainRootScope`
- `DomainControllerScope`
- `PrivilegedScope`
- `ServerScope`
- `GeneralScope`
- `Tier0Scope`
- `Tier1Scope`
- `BroadTrustee`
- `GpoDelegation`
- `GpoControlPath`
- `GpoWmiFilter`
- `GpoLoopback`
- `GpoPreference`
- `CredentialExposure`
- `LocalAdminModification`
- `ScheduledTaskExecution`
- `ServiceControl`

## Static Dashboard State

All current posture domains are included in the generated dashboard payload. `Open-ADPostureDashboard` opens the selected local HTML page directly and does not start a localhost service.

## Server Baseline Future Work

- The first release does not export server baseline collector/import commands and does not instruct operators to run tooling on Domain Controllers.
- Existing baseline parser/collector code is retained only as experimental future-work material.
- A supported future increment requires governed baseline scoping, execution-location design, rollback evidence, and operational validation before reactivation.

Supported ACL filters:

- `q`
- `right`
- `severity`
- `tag`
- `target`
- `trustee`
- `inherited`
- `drift`

Trustee searches include trustee name, SID, DN, and preserved raw trustee string.

Target searches include target name, DN, canonical name, and SID where available.

Drift searches include `New`, `Changed`, `Unchanged`, and `Missing` when ACL comparison data is present.

GPO filters:

- `q`
- `type`
- `severity`
- `tag`
- `gpo`
- `scope`
- `scopeTier`
- `trustee`

ADCS posture is opt-in through:

```powershell
Invoke-ADPostureAudit -IncludeAdcsPosture
```

Current ADCS posture scope:

- Reads certificate templates from `CN=Certificate Templates,CN=Public Key Services,CN=Services,<configurationNamingContext>`.
- Reads Enrollment Services CA objects from `CN=Enrollment Services,CN=Public Key Services,CN=Services,<configurationNamingContext>`.
- Reads `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,<configurationNamingContext>`.
- Associates certificate templates with CAs through the CA `certificateTemplates` publication list.
- Reads CA registry/policy configuration best-effort through Remote Registry, including `EditFlags`, `RequestDisposition`, `InterfaceFlags`, and whether `EDITF_ATTRIBUTESUBJECTALTNAME2` is enabled.
- Reads template enrollment/control ACEs where the AD provider can expose the template security descriptor.
- Reports broad enrollment and broad autoenrollment on authentication-capable templates.
- Reports ESC1-like authentication templates when broad enrollment, enrollee-supplied subject/SAN, authentication-capable EKU, and no issuance gate are present together.
- Reports Any Purpose and no-EKU templates with broad enrollment and no issuance gate.
- Reports broad enrollment-agent templates, exportable authentication private keys, broad template-control delegation, broad Enrollment Services CA object control, broad NTAuth control, ESC6 CA request-SAN configuration, and ESC6 chains that combine CA-level SAN acceptance with published authentication templates.
- Adds `EscTechnique` and ordered `AttackPath` steps to ADCS findings. ACL posture stays generic and does not contain ESC/ADCS interpretation beyond raw ACL evidence.
- Exposes `AdcsTemplates`, `AdcsCas`, `AdcsNtAuth`, and `AdcsFindings` in snapshots/dashboard payloads.
- Exports `*-adcs-findings.csv` when ADCS posture is collected.
- Exports `*-adcs-cas.csv` when ADCS posture is collected.
- Renders ADCS posture in `dashboard/adcs.html`.

Current ADCS filters:

- `q`
- `type`
- `pattern`
- `severity`
- `tag`
- `template`
- `principal`

## Kerberos/Auth Posture State

Kerberos/Auth posture is opt-in through:

```powershell
Invoke-ADPostureAudit -IncludeKerberosAuthPosture
```

Current Kerberos/Auth posture scope:

- Reads authentication-sensitive users, computers, gMSAs, and sMSAs.
- Reports AS-REP roastable accounts from `DONT_REQ_PREAUTH`.
- Reports Kerberoastable service principals from SPN-bearing identities.
- Reports DES-only and RC4/no-AES Kerberos encryption posture from UAC and `msDS-SupportedEncryptionTypes`.
- Reports unconstrained delegation, constrained delegation, and resource-based constrained delegation.
- Reports privileged accounts that are not marked non-delegable and are not identified as Protected Users members.
- Keeps the module read-only: no ticket requests, password spraying, hash extraction, cracking, packet capture, or authentication attempts.
- Adds Kerberos/Auth findings into Object Risk evidence and readiness controls.
- Exposes Kerberos/Auth findings through the static dashboard.

Current normalized Kerberos/Auth findings:

- `KerberosAsRepRoastableAccount`
- `KerberosRoastableServiceAccount`
- `KerberosDesOnlyAccount`
- `KerberosRc4OnlyOrNoAes`
- `KerberosUnconstrainedDelegation`
- `KerberosConstrainedDelegation`
- `KerberosResourceBasedConstrainedDelegation`
- `KerberosSensitiveAccountDelegable`

Current Kerberos/Auth filters:

- `q`
- `type`
- `severity`
- `tag`
- `principal`
- `delegation`
- `encryption`
- `tier`

Recent local validation covers direct static opening, embedded dashboard payloads, filters, and synthetic posture findings.

## Test State

Recent verification:

```powershell
Import-Module Pester
Invoke-Pester -Path .\tests
```

Expected current result:

- 180 tests passed.
- 0 failed.

Project checks:

```powershell
.\scripts\Invoke-ProjectChecks.ps1
```

Known warning:

- None in the current local project check when PSScriptAnalyzer is installed in the user module path.

Latest project check used:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-ProjectChecks.ps1
```

Result:

- 180 tests passed.
- 0 failed.

## Important Constraints

- Do not copy code from external/reference scripts. Use them only for understanding coverage gaps.
- Keep ACL posture opt-in until collector scope and performance are mature.
- Keep payloads free of secrets, especially LAPS password values.
- Preserve static/offline dashboard support.
- Avoid reverting unrelated user changes in the worktree.
