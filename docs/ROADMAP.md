# Roadmap

This roadmap is intentionally product-oriented. The first public release is the static/offline Active Directory posture product. Platform evolution remains documented separately and is not part of the active implementation.

## First Release Readiness

- Static dashboard workflow is stable for local/offline use.
- Generated reports, dashboard payloads, local exception files, timeline data, and sensitive artifacts remain ignored by Git.
- CI/project checks include PSScriptAnalyzer, Pester, module manifest validation, and GitHub readiness checks.
- Synthetic data is used for screenshots, demos, issues, and documentation.
- Sensitive outputs include classification and retention guidance.

## Delivered Posture Domains

### Sensitive Groups

- Sensitive-group membership audit with direct and nested path analysis.
- Tier 0 / Tier 1 / Tier 2 classification.
- Safe membership remediation scripts using the proven direct parent group.
- Orphaned sensitive-group findings for empty privileged groups.
- Approved exceptions, readiness controls, Object Risk, dashboard, CSV export, and Action Plan coverage.

### Identity Risk

- Identity-risk findings from account age, last logon, password age, adminCount, delegation, SPNs, UAC flags, authentication options, and privileged SIDHistory.
- Explainable score components and Object Risk evidence.
- Approved exceptions, readiness controls, dashboard payloads, and CSV export.

### ACL Posture

- Opt-in ACL posture for domain root, AdminSDHolder, scanned sensitive groups, and explicit target expansions.
- Dangerous ACE analysis for GenericAll, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights, ResetPassword, DCSync, delete, membership/SPN writes, account-control writes, LAPS/secret attributes, unexpected owners, and dangerous inheritance.
- Effective trustee expansion with bounded samples in dashboard payloads and full CSV export.
- ACL drift comparison and timeline integration.
- Redacted export mode for sensitive ACL evidence, including raw SDDL/security descriptor fields when present.
- Object Risk, readiness controls, approved exceptions, dashboard, CSV export, and Action Plan playbooks.

### GPO Posture

- GPO container/link posture, SYSVOL path validation, security filtering, delegated control, settings review, WMI filters, loopback processing, script content review, and Group Policy Preferences review.
- GPO findings are correlated with scope criticality and Object Risk.
- Dashboard, CSV export, approved exceptions, readiness controls, and Action Plan playbooks are implemented.

### ADCS Posture

- Certificate template posture for broad enrollment/autoenrollment, authentication-capable EKUs, enrollee-supplied subject/SAN, issuance gates, enrollment-agent exposure, exportable private keys, broad template-control delegation, Any Purpose/no-EKU templates, Enrollment Services CAs, CA object ACLs, NTAuth control, CA SAN configuration, and ESC-style path chaining.
- ADCS inventory, dashboard, CSV export, approved exceptions, readiness controls, Object Risk, and Action Plan playbooks are implemented.

### Kerberos/Auth Posture

- Read-only Kerberos/Auth posture for AS-REP roastable accounts, Kerberoastable service principals, weak Kerberos encryption, unconstrained/constrained delegation, resource-based constrained delegation, and privileged-account delegation protection gaps.
- No ticket requests, password spraying, hash extraction, cracking, packet capture, or authentication attempts.
- Dashboard, CSV export, Object Risk, readiness controls, and approved exceptions are implemented.

### Trusts

- Trust posture for domain and forest trusts, transitivity, SID filtering, selective authentication, external/forest trusts, TGT delegation, stale trust governance, and blast-radius scoring.
- Trust findings feed snapshot/dashboard payloads, CSV export, Object Risk, readiness controls, approved exceptions, and `dashboard/trusts.html`.
- `dashboard/trust.html` remains as a lightweight redirect entry.

### DNS

- DNS posture for AD-integrated DNS zones/records, parsed `dnsRecord` evidence, insecure dynamic updates, aging/scavenging gaps, wildcard records, dangling external aliases, privileged SRV records, stale records, DnsAdmins exposure, and DNS ACL delegation.
- Dashboard, CSV export, Object Risk, readiness controls, approved exceptions, and Action Plan playbooks are implemented.

### Server Baseline Collection

- Future / not in v1.
- The experimental code is retained for later design, but no public v1 workflow imports Microsoft SCT packages or runs local baseline collection on Domain Controllers.
- Reactivation requires a separate security design for baseline filtering, execution location, governance, rollback evidence, and validation.

## Delivered Governance And Reporting

- Snapshot schema `1.3` adds posture summary, orphaned sensitive-group findings, framework mappings, framework summary, and remediation playbooks.
- Governed crosswalk catalog for NIST CSF, ISO 27001, SOC 2, and CIS Controls is versioned in `config/FrameworkCrosswalk.json`.
- Executive dashboard includes exposure narrative, collection coverage, domain breakdown, exceptions, ATT&CK context, framework mappings, top actions, and methodology limitations.
- `Invoke-ADPostureArtifactRetention` provides 180-day default local retention inventory, explicit removal, path protection, and removal logs.
- `scripts/Test-ADPostureSyntheticScale.ps1` provides reproducible synthetic scale and precision validation.

## External Environmental Validation

The first release is code-complete for static/offline delivery. The following are external validation activities that require customer/lab environments and are not implementation blockers:

- Validate ACL Collector v2 against real domains and tune query pacing per environment.
- Validate expanded GPO posture against real WMI filters, loopback, GPP tasks/services/groups, SYSVOL scripts, and external paths.
- Validate ADCS posture against real Enterprise CAs, published/unpublished templates, NTAuth delegation, Any Purpose/no-EKU templates, ESC-style malicious templates, and variable Remote Registry/firewall permissions.
- Validate DNS posture and DNS parser output against real AD-integrated DNS zones, mixed record classes, older DNS versions, DnsAdmins membership, delegated DNS ACLs, wildcard records, and stale/dangling aliases.
- Validate future server baseline collection across supported Windows Server versions, GPO-enforced settings, Defender/EDR variance, audit policy output, and firewall/RDP/WinRM posture.
- Validate the Microsoft SCT importer against additional official Windows Server 2019/2022/2025 baseline ZIPs and tune unsupported file format reporting if encountered.

## Platform Evolution

Platform evolution is explicitly deferred and is not part of v1. Do not implement database, backend, RBAC, service-mode, API, webhook, SIEM, Jira, ServiceNow, continuous monitoring, scheduled collection, or multiuser application work without a new approved scope.
