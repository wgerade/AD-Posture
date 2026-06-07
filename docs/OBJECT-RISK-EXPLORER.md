# Object Risk Explorer

Object Risk Explorer is the next posture domain for AD Posture. It shifts the product from a sensitive-group queue to an object-centric risk profile for users, groups, computers, service accounts, OUs, GPOs, and high-impact directory containers.

The goal is to answer one question clearly:

```text
Which AD object should be reviewed first, why is it risky, and what evidence supports that conclusion?
```

## Product Shape

Each object should have a dedicated profile with:

- Object identity: name, SID, DN, object class, domain, owner hints, creation/change dates.
- Risk summary: object score, severity, tier, tags, and remediation difficulty.
- Explainable reasons: one row per evidence-backed risk factor.
- Effective privileges: direct and indirect group membership, privileged reachability, sensitive ACLs, and GPO/OU exposure.
- Hygiene signals: stale status, password age, UAC flags, delegation, SPNs, description quality, and disabled/locked state.
- Related objects: parent OU/container, managedBy, group nesting, ACL trustees, affected targets, and risky paths.
- Recommended action: review, remove membership, disable, rotate, document exception, reduce ACL, or investigate ownership.

## Authoritative Inputs

Object Risk Explorer must be built from explicit collector contracts and authoritative platform references, not from historical delivery artifacts.

The current implementation can safely derive the first object model from the module's own `Findings` output because those records already include account type, DN, SID, privilege tier, score components, UAC flags, dates, group membership chain, and remediation actions.

Future collectors should be specified independently before implementation. Each collector must define:

- The authoritative AD attributes, control OIDs, schema classes, rights GUIDs, or protocol structures it reads.
- The minimum permissions required to collect the data.
- Whether the data is raw evidence, normalized evidence, or presentation-only enrichment.
- How sensitive values are redacted, encrypted, or intentionally not collected.
- How the collector behaves when a schema extension or feature is not present.

Historical scripts, spreadsheets, and slide decks can be useful as memory of past reporting needs, but they are not schemas, source-of-truth collectors, or implementation baselines for this project.

## Target Signal Domains

This list is intentionally not a closed checklist. It is the set of domains that Object Risk Explorer should grow toward, with each domain implemented through a reviewed collector contract.

- Identity attributes: object identity, object class/category, SID, GUID, DN, account status, creation/change dates, ownership hints, descriptive metadata, and governance ownership.
- Authentication and account controls: UAC flags, password age, password policy context, pre-authentication posture, smart card requirements, lockout/disabled state, and logon restrictions.
- Privilege membership: direct and transitive sensitive group membership, nesting depth, effective privilege tier, native AD principals, and exception state.
- Service identity posture: user-style service accounts, gMSA, sMSA, SPNs, delegation, Kerberos encryption posture, ownership, and interactive logon exposure.
- ACL posture: raw security descriptors, owner/group, control flags, DACL/SACL sections when permitted, ACE ordering, inherited/effective state, trustee and target resolution, object-specific rights, and extended rights.
- GPO posture: GPO delegation, links, enforcement, disabled sections, WMI filters, security filtering, scripts, policy settings, local group membership changes, and affected object scope.
- OU and container posture: delegated administration, inheritance boundaries, protected ACLs, Tier 0/Tier 1 scope, and child object exposure.
- Computer posture: domain controllers, privileged servers, workstation tiers, stale computer accounts, delegation, local administrator password management, and management-plane exposure.
- Trust and domain posture: trust direction/type/transitivity, SID filtering, selective authentication, external/forest trust exposure, and trust object protection.
- Certificate Services posture: CA objects, certificate templates, enrollment rights, dangerous template settings, NTAuth/Enrollment Services objects, and ESC-style privilege paths.
- DNS and directory-integrated service posture: AD-integrated DNS zones, DnsAdmins exposure, dynamic update posture, and privileged service records where relevant.
- Privileged access workflow: approved exceptions, temporary standing access, expiry, ownership, ticketing, and audit trail.
- Data quality: orphaned SIDs, unresolved trustees, deleted-object remnants, duplicate names, stale metadata, missing owners, and objects that cannot be confidently classified.

## Modern LAPS Scope

LAPS analysis must explicitly support both legacy Microsoft LAPS and Windows LAPS without treating the old `ms-Mcs-*` attributes as the current model.

Windows LAPS target signals include:

- `msLAPS-PasswordExpirationTime`
- `msLAPS-Password`
- `msLAPS-EncryptedPassword`
- `msLAPS-EncryptedPasswordHistory`
- `msLAPS-EncryptedDSRMPassword`
- `msLAPS-EncryptedDSRMPasswordHistory`
- `msLAPS-CurrentPasswordVersion` when the forest schema supports it
- `ms-LAPS-Encrypted-Password-Attributes` extended right

Legacy Microsoft LAPS target signals include:

- `ms-Mcs-AdmPwdExpirationTime`
- `ms-Mcs-AdmPwd`

Rules:

- Never collect or export clear-text LAPS password values into normal dashboard/report payloads.
- Report who can read or write LAPS-related attributes and whether the target objects are Tier 0/Tier 1/Tier 2.
- Distinguish password-read exposure, password-expiration write exposure, encrypted-password attribute exposure, DSRM password exposure, and history exposure.
- Treat Windows LAPS and legacy Microsoft LAPS as separate evidence families that may coexist during migration.
- Record whether the schema elements are absent, present, partially present, or mixed across domains.

## Risk Tags

Initial tags should be deterministic and evidence-backed:

| Tag | Applies to | Source signals |
| --- | --- | --- |
| `Tier0Exposure` | Any object | Domain Admins, Enterprise Admins, Schema Admins, DC, AdminSDHolder, DCSync, Tier 0 group/path |
| `PrivilegedMembership` | User, service account, group, computer | Direct or nested sensitive group membership |
| `IndirectPrivilege` | User, service account, group, computer | Membership chain depth greater than zero |
| `AdminCount` | User, service account, group | `adminCount = 1` |
| `StaleIdentity` | User, service account, computer | Last logon beyond stale threshold or no usable logon |
| `OldPassword` | User, service account, computer | Password age beyond configured threshold |
| `PasswordNeverExpires` | User, service account, computer | `PasswordNeverExpires` or UAC bit |
| `NoPreAuth` | User, service account | `DoesNotRequirePreAuth` |
| `Kerberoastable` | User, service account | SPN present on a user-style principal |
| `DelegationRisk` | User, service account, computer | Trusted for delegation or trusted to auth for delegation |
| `WeakKerberos` | User, service account, computer | DES-only or weak encryption flags |
| `SensitiveAclTrustee` | User, group, computer | Trustee has dangerous ACE over another sensitive target |
| `SensitiveAclTarget` | User, group, computer, OU, GPO, domain root | Object is controlled through dangerous ACE |
| `DCSyncCapable` | User, group, service account | Replication extended rights on domain naming context |
| `WindowsLapsExposure` | User, group, computer | Windows LAPS password, encrypted password, DSRM, history, or encrypted-password attribute exposure |
| `LegacyLapsExposure` | User, group, computer | Legacy Microsoft LAPS password or expiration attribute exposure |
| `UnexpectedOwner` | Any sensitive ACL target | Non-built-in owner can alter the target DACL and potentially grant itself control |
| `EmptyPrivilegedGroup` | Group | Empty group with privileged ACL or sensitive group classification |
| `OwnershipGap` | Any object | Missing manager/managedBy/description where governance requires ownership |
| `UnresolvedTrustee` | ACL trustee | SID or trustee could not be resolved with confidence |
| `SchemaFeatureGap` | Domain, forest, computer | Expected schema or feature signal is absent, partial, or mixed |

## Scoring Model

Object score should aggregate evidence from multiple domains while preserving explainability.

```text
ObjectRiskScore =
  MembershipExposure
  + AccountHygieneRisk
  + AclTrusteeRisk
  + AclTargetRisk
  + GpoExposureRisk
  + Trust/DomainContextRisk
  - ApprovedExceptionOffset
```

Rules:

- Never store a score without storing the contributing evidence rows.
- Keep existing finding-level membership scoring as a component, not as the entire object score.
- Score should be unbounded and cumulative, consistent with the current exposure model.
- Disabled/stale objects can reduce exploitability but should not erase sensitive ACL or ownership risk.
- Approved exceptions should suppress actionable priority only when active, scoped, owner-backed, and expiring.

## Normalized Snapshot Contract

Before a database exists, the file-based snapshot can evolve with additive fields:

```json
{
  "SchemaVersion": "1.1",
  "Objects": [
    {
      "ObjectId": "domainSid:objectSid",
      "Domain": "corp.example.com",
      "ObjectClass": "user",
      "SamAccountName": "adm.example",
      "DisplayName": "Admin Example",
      "DistinguishedName": "CN=Admin Example,OU=Admins,DC=corp,DC=example,DC=com",
      "ObjectSid": "S-1-5-21-...",
      "PrivilegeTier": "Tier 0",
      "RiskScore": 18.42,
      "Severity": "High",
      "Tags": ["Tier0Exposure", "PasswordNeverExpires", "AdminCount"],
      "EvidenceIds": ["ev-001", "ev-002", "ev-003"]
    }
  ],
  "ObjectEvidence": [
    {
      "EvidenceId": "ev-001",
      "ObjectId": "domainSid:objectSid",
      "EvidenceType": "SensitiveGroupMembership",
      "SourceDomain": "SensitiveGroups",
      "Score": 5.6,
      "Severity": "High",
      "Reason": "Indirect member of Domain Admins through 2 nested groups.",
      "Remediation": "Validate business need or remove nested membership.",
      "Path": ["adm.example", "IT Admins", "Domain Admins"]
    }
  ],
  "ObjectRelationships": [
    {
      "FromObjectId": "domainSid:trusteeSid",
      "ToObjectId": "domainSid:targetSid",
      "RelationshipType": "GenericAll",
      "SourceDomain": "ACL",
      "IsInherited": false
    }
  ]
}
```

## V1 Boundary

The Object Risk Explorer in v1 is static/offline. It is built from snapshot arrays, local dashboard JavaScript, CSV/JSON exports, and governed exception metadata. Database, API, service-mode, RBAC, and multiuser workflows are deferred platform work and are not part of this release.
8. Add exception workflow and audit logs.

This keeps the current tool useful offline while creating a clean path to a full posture platform.
