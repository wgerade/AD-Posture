# User Account Control (UAC) — flag assessment framework

Each flag is evaluated for **privileged-group audits** (Domain Admins, Enterprise Admins, etc.):

| Dimension | Meaning |
|-----------|---------|
| **Risk weight** | Adds 0–1.0 to UAC risk bonus (feeds membership score) |
| **Remediation** | Low / Medium / High — effort to fix safely |
| **Dashboard** | Show in UAC flags column? |
| **Privileged concern** | Especially suspicious on tier-0 / tier-1 accounts |

Duplicate columns: flags already shown under **Status**, **Pwd never expires**, or **Pwd last set** are hidden in the UI but still counted in UAC risk where relevant.

---

## Account type bits (category only — not listed as findings)

| Bit | Name | Category label |
|-----|------|----------------|
| 0x0200 | NORMAL_ACCOUNT | Normal Account |
| 0x1000 | WORKSTATION_TRUST_ACCOUNT | Workstation Trust Account |
| 0x2000 | SERVER_TRUST_ACCOUNT | Server Trust Account |
| 0x0800 | INTERDOMAIN_TRUST_ACCOUNT | Interdomain Trust Account |
| 0x0100 | TEMP_DUPLICATE_ACCOUNT | Temporary Duplicate Account |

---

## Security and operational flags

| Bit | Name | Risk | Remediation | Dashboard | Rationale (privileged account context) |
|-----|------|------|-------------|-----------|----------------------------------------|
| 0x0001 | SCRIPT | **0.45** | Low | Yes | Logon script at sign-in — on DA/EA uncommon; may indicate persistence (GPO/logon script hijack). Review `scriptPath`, GPO, and who can change it. |
| 0x0002 | ACCOUNTDISABLE | 0.15 | Low | No* | Disabled — shown in Status. Still in group until removed. |
| 0x0008 | HOMEDIR_REQUIRED | 0.10 | Low | Yes | Legacy — home directory required at logon; weak signal alone, document if unexpected. |
| 0x0010 | LOCKOUT | 0.35 | Low | Yes | Locked out — brute-force or abuse indicator; investigate before unlock. |
| 0x0020 | PASSWD_NOTREQD | **0.85** | Medium | Yes | No password required — critical on privileged accounts. |
| 0x0040 | PASSWD_CANT_CHANGE | **0.55** | Medium | Yes | User cannot change password — service-like; complicates rotation on admins. |
| 0x0080 | ENCRYPTED_TEXT_PWD_ALLOWED | **0.90** | Medium | Yes | Reversible encryption — credential exposure risk; disable unless legacy app requires. |
| 0x10000 | DONT_EXPIRE_PASSWORD | **0.50** | Medium | No* | Password never expires — shown in Pwd never expires column. |
| 0x20000 | MNS_LOGON_ACCOUNT | 0.20 | Low | Yes | MNS logon account — rare; legacy cluster/messaging; verify legitimacy. |
| 0x40000 | SMARTCARD_REQUIRED | **-0.15** | Medium | Yes | Hardening — smart card required (reduces UAC risk bonus). |
| 0x80000 | TRUSTED_FOR_DELEGATION | **1.00** | High | Yes | Unconstrained delegation — severe; attacker can abuse TGT. Remove or constrain. |
| 0x100000 | NOT_DELEGATED | **-0.20** | Low | Yes | Hardening — account is sensitive and cannot be delegated. |
| 0x200000 | USE_DES_KEY_ONLY | **0.75** | Medium | Yes | Weak Kerberos (DES) - crackable tickets; upgrade to AES-only. |
| 0x400000 | DONT_REQ_PREAUTH | **0.95** | High | Yes | No Kerberos pre-auth — AS-REP roasting; disable pre-auth only if required. |
| 0x800000 | PASSWORD_EXPIRED | 0.25 | Low | No* | Password expired — overlap with Pwd last set when stale. |
| 0x1000000 | TRUSTED_TO_AUTH_FOR_DELEGATION | **0.80** | High | Yes | Constrained delegation auth — review SPNs and allowed services. |

\*Hidden in UAC flags when another column already shows the same fact.

---

## Combined risk (UAC bonus)

- Sum of active flag **risk weights** (including hardening negatives).
- Capped **UAC bonus**: 0–**1.5** added to membership risk formula.
- **Remediation difficulty** for the row = max(flag remediation, group default).

---

## Examples

| Account | UAC flags | Interpretation |
|---------|-----------|----------------|
| Domain Admin + SCRIPT + USE_DES_KEY_ONLY | High | Unusual admin profile: persistence vector + weak Kerberos — prioritize review. |
| Domain Admin + TRUSTED_FOR_DELEGATION | Critical | Tier-0 with unconstrained delegation — top remediation priority. |
| Domain Admin + NOT_DELEGATED + SMARTCARD_REQUIRED | Lower UAC bonus | Hardened admin pattern — still review group membership. |

Configuration source of truth: `config/UserAccountControlFlags.json`.

Dashboard display uses friendly comma-separated labels, for example `Normal Account, Weak Kerberos (DES)`.
