/* Synthetic demo data for the public AD Posture guided tour. Safe for screenshots and GitHub Pages.
   This bundle is only used as a last-resort fallback when no generated audit data is available. */
window.__AD_DEMO_DATA__ = {
  findings: [
    {
      Timestamp: '2026-06-10T09:00:00-05:00', Domain: 'corp.example', SensitiveGroup: 'Domain Admins', GroupTier: 'Domain', PrivilegeTier: 'Tier 0', PrivilegeTierReason: 'Domain Admins', GroupRiskWeight: 5,
      MemberSam: 'adm.breakglass01', MemberDisplay: 'Admin Breakglass 01', MemberDn: 'CN=Admin Breakglass 01,OU=Demo Identities,DC=corp,DC=example', ObjectSid: 'S-1-5-21-demo-5001', AccountType: 'User (AdminCount)',
      IsDirect: true, NestingDepth: 0, MembershipChain: 'Domain Admins -> Admin Breakglass 01', AccountStatus: 'Active', IsEnabled: true, IsDisabled: false, IsStale: false,
      DaysSinceLogon: 7, LastLogonDisplay: '06/03/2026 (7 days)', PasswordLastSetDisplay: '04/18/2025 (418 days)', PasswordNeverExpires: true,
      UserAccountControlSummary: 'Normal Account, Password Never Expires', UacRiskBonus: 0.8, RiskScore: 8.4, RemediationDifficulty: 'High',
      CleanupActions: 'Replace standing membership with JIT approval and vault-controlled break-glass rotation.', SuggestedRemediation: 'Replace standing membership with JIT approval and vault-controlled break-glass rotation.',
      WhyThisMatters: 'Standing Tier 0 membership can become full domain compromise if the account is abused.', TechnicalRisk: 'Standing Tier 0 membership can become full domain compromise if the account is abused.',
      AttackTechniques: [{ Id: 'T1098', Name: 'Account Manipulation', Tactic: 'Persistence' }], ScoreFormula: 'Base 5 + privileged account + UAC factors = 8.4', ScoreComponents: { Base: 5, UacBonus: 0.8, Final: 8.4 }
    },
    {
      Timestamp: '2026-06-10T09:00:00-05:00', Domain: 'corp.example', SensitiveGroup: 'Domain Admins', GroupTier: 'Domain', PrivilegeTier: 'Tier 0', PrivilegeTierReason: 'Domain Admins', GroupRiskWeight: 5,
      MemberSam: 'svc.backup.archive', MemberDisplay: 'Archive Backup Service', MemberDn: 'CN=Archive Backup Service,OU=Service Accounts,DC=corp,DC=example', ObjectSid: 'S-1-5-21-demo-5002', AccountType: 'ServiceAccount',
      IsDirect: false, NestingDepth: 1, MembershipChain: 'Domain Admins -> Backup Operators -> Archive Backup Service', AccountStatus: 'Active', IsEnabled: true, IsDisabled: false, IsStale: false,
      DaysSinceLogon: 3, LastLogonDisplay: '06/07/2026 (3 days)', PasswordLastSetDisplay: '11/20/2024 (567 days)', PasswordNeverExpires: false,
      UserAccountControlSummary: 'Normal Account, Weak Kerberos (DES)', UacRiskBonus: 1.5, RiskScore: 9.8, RemediationDifficulty: 'High',
      CleanupActions: 'Remove nested privilege path and redesign service access with least privilege.', SuggestedRemediation: 'Remove nested privilege path and redesign service access with least privilege.',
      WhyThisMatters: 'A service account with weak Kerberos settings and Tier 0 reach increases credential theft impact.', TechnicalRisk: 'Weak Kerberos and Tier 0 reach increase credential theft impact.',
      AttackTechniques: [{ Id: 'T1558', Name: 'Steal or Forge Kerberos Tickets', Tactic: 'Credential Access' }], ScoreFormula: 'Base 5 + service account + nesting + weak Kerberos = 9.8', ScoreComponents: { Base: 5, ServiceAccount: 1.2, NestingBonus: 1, UacBonus: 1.5, Final: 9.8 }
    },
    {
      Timestamp: '2026-06-10T09:00:00-05:00', Domain: 'corp.example', SensitiveGroup: 'Administrators', GroupTier: 'Builtin', PrivilegeTier: 'Tier 0', PrivilegeTierReason: 'Builtin Administrators', GroupRiskWeight: 5,
      MemberSam: 'grp.workstation-admins', MemberDisplay: 'Workstation Admins', MemberDn: 'CN=Workstation Admins,OU=Groups,DC=corp,DC=example', ObjectSid: 'S-1-5-21-demo-5003', AccountType: 'Group',
      IsDirect: false, NestingDepth: 1, MembershipChain: 'Administrators -> Workstation Admins -> Helpdesk Tier 2', AccountStatus: 'Active', IsEnabled: true, IsDisabled: false, IsStale: false,
      LastLogonDisplay: 'N/A', PasswordLastSetDisplay: 'N/A', UserAccountControlSummary: 'N/A', RiskScore: 6.6, RemediationDifficulty: 'Medium',
      CleanupActions: 'Replace broad nested group with tier-scoped administration groups.', SuggestedRemediation: 'Replace broad nested group with tier-scoped administration groups.',
      WhyThisMatters: 'Nested groups make privileged access harder to govern and review.', TechnicalRisk: 'Nested groups can hide privilege paths.',
      AttackTechniques: [{ Id: 'T1078', Name: 'Valid Accounts', Tactic: 'Defense Evasion' }], ScoreFormula: 'Base 5 + nesting = 6.6'
    },
    {
      Timestamp: '2026-06-10T09:00:00-05:00', Domain: 'corp.example', SensitiveGroup: 'Group Policy Creator Owners', GroupTier: 'Domain', PrivilegeTier: 'Tier 0', PrivilegeTierReason: 'GPO control path', GroupRiskWeight: 4,
      MemberSam: 'jane.admin', MemberDisplay: 'Jane Admin', MemberDn: 'CN=Jane Admin,OU=Admins,DC=corp,DC=example', ObjectSid: 'S-1-5-21-demo-5004', AccountType: 'User (AdminCount)',
      IsDirect: true, NestingDepth: 0, MembershipChain: 'Group Policy Creator Owners -> Jane Admin', AccountStatus: 'Active', IsEnabled: true, IsDisabled: false, IsStale: false,
      LastLogonDisplay: '06/01/2026 (9 days)', PasswordLastSetDisplay: '03/02/2026 (100 days)', UserAccountControlSummary: 'Normal Account, Cannot Be Delegated', RiskScore: 5.9, RemediationDifficulty: 'Medium',
      CleanupActions: 'Move GPO creation through controlled change workflow.', SuggestedRemediation: 'Move GPO creation through controlled change workflow.',
      WhyThisMatters: 'GPO creation rights can influence privileged computers and users.', TechnicalRisk: 'GPO rights can alter security posture at scale.',
      AttackTechniques: [{ Id: 'T1484', Name: 'Domain Policy Modification', Tactic: 'Defense Evasion' }], ScoreFormula: 'Base 4 + privileged GPO control = 5.9'
    },
    {
      Timestamp: '2026-06-10T09:00:00-05:00', Domain: 'corp.example', SensitiveGroup: 'Backup Operators', GroupTier: 'Domain', PrivilegeTier: 'Tier 1', PrivilegeTierReason: 'Backup Operators', GroupRiskWeight: 4,
      MemberSam: 'svc.file.backup', MemberDisplay: 'File Backup gMSA', MemberDn: 'CN=File Backup gMSA,OU=Service Accounts,DC=corp,DC=example', ObjectSid: 'S-1-5-21-demo-5005', AccountType: 'ServiceAccount (gMSA)',
      IsDirect: true, NestingDepth: 0, MembershipChain: 'Backup Operators -> File Backup gMSA', AccountStatus: 'Active', IsEnabled: true, IsDisabled: false, IsStale: false,
      LastLogonDisplay: '06/05/2026 (5 days)', PasswordLastSetDisplay: 'Managed', UserAccountControlSummary: 'Normal Account', RiskScore: 4.2, RemediationDifficulty: 'Medium',
      CleanupActions: 'Validate backup scope and remove interactive logon where possible.', SuggestedRemediation: 'Validate backup scope and remove interactive logon where possible.',
      WhyThisMatters: 'Backup privileges may expose sensitive data and enable restore abuse.', TechnicalRisk: 'Backup privileges may enable sensitive data access.',
      AttackTechniques: [{ Id: 'T1006', Name: 'Direct Volume Access', Tactic: 'Defense Evasion' }], ScoreFormula: 'Base 4 + service account context = 4.2'
    },
    {
      Timestamp: '2026-06-10T09:00:00-05:00', Domain: 'corp.example', SensitiveGroup: 'Remote Desktop Users', GroupTier: 'Builtin', PrivilegeTier: 'Tier 2', PrivilegeTierReason: 'Remote Desktop Users', GroupRiskWeight: 2,
      MemberSam: 'contractor.ops', MemberDisplay: 'Contractor Ops', MemberDn: 'CN=Contractor Ops,OU=Contractors,DC=corp,DC=example', ObjectSid: 'S-1-5-21-demo-5006', AccountType: 'User',
      IsDirect: true, NestingDepth: 0, MembershipChain: 'Remote Desktop Users -> Contractor Ops', AccountStatus: 'Active', IsEnabled: true, IsDisabled: false, IsStale: true,
      DaysSinceLogon: 245, LastLogonDisplay: '10/08/2025 (245 days)', PasswordLastSetDisplay: '01/12/2025 (514 days)', UserAccountControlSummary: 'Normal Account', RiskScore: 2.1, RemediationDifficulty: 'Low',
      CleanupActions: 'Validate business need and set expiration on access.', SuggestedRemediation: 'Validate business need and set expiration on access.',
      WhyThisMatters: 'Remote access should be time-bound and tied to an accountable owner.', TechnicalRisk: 'Stale remote access increases exposure.',
      AttackTechniques: [{ Id: 'T1021', Name: 'Remote Services', Tactic: 'Lateral Movement' }], ScoreFormula: 'Base 2 + stale access = 2.1'
    }
  ],
  groups: [
    { SensitiveGroup: 'Domain Admins', Tier: 'Domain', PrivilegeTier: 'Tier 0', MemberCount: 2, ExcludedCount: 0, AverageRiskScore: 9.1, AggregateRiskScore: 18.2, RiskWeight: 5 },
    { SensitiveGroup: 'Administrators', Tier: 'Builtin', PrivilegeTier: 'Tier 0', MemberCount: 1, ExcludedCount: 0, AverageRiskScore: 6.6, AggregateRiskScore: 6.6, RiskWeight: 5 },
    { SensitiveGroup: 'Group Policy Creator Owners', Tier: 'Domain', PrivilegeTier: 'Tier 0', MemberCount: 1, ExcludedCount: 0, AverageRiskScore: 5.9, AggregateRiskScore: 5.9, RiskWeight: 4 },
    { SensitiveGroup: 'Backup Operators', Tier: 'Domain', PrivilegeTier: 'Tier 1', MemberCount: 1, ExcludedCount: 0, AverageRiskScore: 4.2, AggregateRiskScore: 4.2, RiskWeight: 4 },
    { SensitiveGroup: 'Remote Desktop Users', Tier: 'Builtin', PrivilegeTier: 'Tier 2', MemberCount: 1, ExcludedCount: 0, AverageRiskScore: 2.1, AggregateRiskScore: 2.1, RiskWeight: 2 }
  ],
  exceptions: [
    { ApprovedExceptionStatus: 'Active', SensitiveGroup: 'Domain Admins', MemberSam: 'adm.breakglass02', MemberDisplay: 'Admin Breakglass 02', RiskScore: 7.4, ApprovedExceptionOwner: 'Identity Operations', ApprovedExceptionApprovedBy: 'CISO', ApprovedExceptionTicket: 'CHG-2026-0042', ApprovedExceptionExpiresAt: '2026-12-31', ApprovedExceptionReason: 'Break-glass account with vault control and quarterly validation.' },
    { ApprovedExceptionStatus: 'Expired', SensitiveGroup: 'Backup Operators', MemberSam: 'svc.archive.backup', MemberDisplay: 'Archive Backup Service', RiskScore: 3.6, ApprovedExceptionOwner: 'Infrastructure', ApprovedExceptionApprovedBy: 'Security Architecture', ApprovedExceptionTicket: 'CHG-2025-1199', ApprovedExceptionExpiresAt: '2026-04-30', ApprovedExceptionReason: 'Legacy backup migration window elapsed.' }
  ],
  monitoring: [
    { ExclusionReason: 'Native AD architecture', SensitiveGroup: 'Domain Controllers', MemberSam: 'DC01$', MemberDisplay: 'DC01', NativeIdentityCategory: 'Domain controller computer', NativeIdentityReason: 'Domain controller membership is expected and monitored separately.', ObjectSid: 'S-1-5-21-demo-domain-516', AccountType: 'Computer (DomainController)', RiskScore: 0 }
  ],
  aclFindings: [
    { AclFindingId: 'acl-demo-000001', Domain: 'corp.example', FindingType: 'DangerousAce', Severity: 'Critical', RiskScore: 12.4, TargetName: 'AdminSDHolder', TargetDistinguishedName: 'CN=AdminSDHolder,CN=System,DC=corp,DC=example', TargetObjectClass: 'container', TrusteeName: 'Delegated Admins', TrusteeObjectClass: 'group', ActiveDirectoryRights: 'WriteDacl', AccessControlType: 'Allow', IsInherited: false, Reason: 'Delegated Admins can change the DACL on AdminSDHolder, impacting protected accounts.', Remediation: 'Remove unexpected WriteDacl and restrict changes to Tier 0 administrators.', ScoreFormula: 'ACL score = sensitive target + WriteDacl + non-inherited ACE', Tags: ['ACL', 'AdminSDHolder', 'WriteDacl'] },
    { AclFindingId: 'acl-demo-000002', Domain: 'corp.example', FindingType: 'UnexpectedOwner', Severity: 'High', RiskScore: 7.9, TargetName: 'AXZ', TargetDistinguishedName: 'CN=AXZ,CN=Users,DC=corp,DC=example', TargetObjectClass: 'user', TrusteeName: 'CORP\\HelpdeskUser', TrusteeObjectClass: 'user', ActiveDirectoryRights: 'Owner', AccessControlType: 'Owner', Reason: 'Unexpected owner on a sensitive account can allow permission takeover.', Remediation: 'Reset owner to an approved Tier 0 administrative group.', ScoreFormula: 'ACL score = sensitive object + unexpected owner', Tags: ['ACL', 'Owner'] }
  ],
  gpos: [{ DisplayName: 'Tier 0 Workstation Control Policy', Name: '{DEMO-GPO-0001}', Guid: 'DEMO-GPO-0001', DistinguishedName: 'CN={DEMO-GPO-0001},CN=Policies,CN=System,DC=corp,DC=example', FileSysPath: '\\\\corp.example\\SYSVOL\\corp.example\\Policies\\{DEMO-GPO-0001}', Status: 'Enabled', WmiFilter: 'corp.example;{DEMO-WMI-0001};Privileged Workstations', HasScripts: true }],
  gpoLinks: [{ GpoDistinguishedName: 'CN={DEMO-GPO-0001},CN=Policies,CN=System,DC=corp,DC=example', LinkOptions: 0, IsLinkDisabled: false, IsEnforced: false, ScopeName: 'Domain Controllers', ScopeDistinguishedName: 'OU=Domain Controllers,DC=corp,DC=example', ScopeObjectClass: 'organizationalUnit' }],
  gpoFindings: [
    { GpoFindingId: 'gpo-demo-000001', Domain: 'corp.example', FindingType: 'GpoDelegationControl', Severity: 'Critical', RiskScore: 11.88, GpoName: 'Tier 0 Workstation Control Policy', GpoGuid: 'DEMO-GPO-0001', GpoStatus: 'Enabled', ScopeName: 'Domain Controllers', ScopeTier: 'Tier 0', TrusteeName: 'Everyone', DelegatedRight: 'GenericAll', Reason: "Trustee 'Everyone' has GenericAll over a GPO linked to Domain Controllers.", Remediation: 'Remove broad GPO delegation and restrict policy editing.', ScoreFormula: 'GPO delegation score = 7.2 * scope 1.65 * trustee 1.2', Tags: ['GpoDelegation', 'Tier0Scope'] },
    { GpoFindingId: 'gpo-demo-000002', Domain: 'corp.example', FindingType: 'GpoPreferenceCredential', Severity: 'Critical', RiskScore: 14.85, GpoName: 'Tier 0 Workstation Control Policy', GpoGuid: 'DEMO-GPO-0001', GpoStatus: 'Enabled', ScopeName: 'Domain Controllers', ScopeTier: 'Tier 0', DelegatedRight: 'Properties', FileSystemPath: '\\\\corp.example\\SYSVOL\\corp.example\\Policies\\{DEMO-GPO-0001}\\Machine\\Preferences\\Groups\\Groups.xml', Reason: 'Group Policy Preference XML contains credential material or a cpassword-like field.', Remediation: 'Remove stored credentials, rotate exposed passwords, and replace with a managed secret process.', ScoreFormula: 'GPO preference score = 9 * scope 1.65', Tags: ['GpoPreference', 'CredentialExposure'] }
  ],
  kerberosAuthPrincipals: [
    { Domain: 'corp.example', Principal: 'svc.backup.archive', PrincipalSam: 'svc.backup.archive', PrincipalClass: 'user', PrincipalDn: 'CN=Archive Backup Service,OU=Service Accounts,DC=corp,DC=example', PrincipalSid: 'S-1-5-21-demo-4101', AccountType: 'ServiceAccount', PrivilegeTier: 'Tier 0', ServicePrincipalNames: ['MSSQLSvc/backup01.corp.example:1433', 'HOST/backup01.corp.example'], DelegationType: 'Unconstrained', EncryptionSummary: 'DES enabled; AES not confirmed' },
    { Domain: 'corp.example', Principal: 'web.portal', PrincipalSam: 'web.portal', PrincipalClass: 'user', PrincipalDn: 'CN=Portal Web Service,OU=Service Accounts,DC=corp,DC=example', PrincipalSid: 'S-1-5-21-demo-4102', AccountType: 'ServiceAccount', PrivilegeTier: 'Tier 1', ServicePrincipalNames: ['HTTP/portal-web.corp.example'], DelegationType: 'Constrained', EncryptionSummary: 'RC4 allowed; AES keys missing' }
  ],
  kerberosAuthFindings: [
    { KerberosAuthFindingId: 'auth-demo-000001', Domain: 'corp.example', FindingType: 'KerberosRoastableServiceAccount', RiskPattern: 'Kerberoastable privileged service account', Severity: 'Critical', RiskScore: 9.4, Principal: 'svc.backup.archive', PrincipalSam: 'svc.backup.archive', PrincipalClass: 'user', PrincipalDn: 'CN=Archive Backup Service,OU=Service Accounts,DC=corp,DC=example', PrincipalSid: 'S-1-5-21-demo-4101', PrivilegeTier: 'Tier 0', AccountType: 'ServiceAccount', DelegationType: 'Unconstrained', ServicePrincipalNames: ['MSSQLSvc/backup01.corp.example:1433', 'HOST/backup01.corp.example'], DelegationTargets: ['Any service'], EncryptionTypes: ['DES', 'RC4'], EncryptionSummary: 'DES/RC4 exposure with privileged reach', Reason: 'Privileged service account has SPNs and weak Kerberos settings.', Remediation: 'Rotate the service account secret, remove weak encryption, and reduce privilege.', ScoreFormula: 'Kerberos score = privileged service account + roastable SPN + weak crypto + delegation', Tags: ['Kerberoast', 'WeakEncryption', 'Delegation', 'Tier0'], AttackTechniques: [{ Id: 'T1558.003', Name: 'Kerberoasting' }] },
    { KerberosAuthFindingId: 'auth-demo-000002', Domain: 'corp.example', FindingType: 'KerberosDelegationRisk', RiskPattern: 'Delegation account with broad target path', Severity: 'High', RiskScore: 7.6, Principal: 'web.portal', PrincipalSam: 'web.portal', PrincipalClass: 'user', PrincipalDn: 'CN=Portal Web Service,OU=Service Accounts,DC=corp,DC=example', PrincipalSid: 'S-1-5-21-demo-4102', PrivilegeTier: 'Tier 1', AccountType: 'ServiceAccount', DelegationType: 'Constrained', ServicePrincipalNames: ['HTTP/portal-web.corp.example'], DelegationTargets: ['CIFS/files01.corp.example', 'HOST/app01.corp.example'], EncryptionTypes: ['RC4', 'AES128'], EncryptionSummary: 'RC4 still allowed', Reason: 'Delegation target list includes infrastructure services.', Remediation: 'Constrain delegation to current dependencies and remove RC4 after rollover.', ScoreFormula: 'Kerberos score = delegation + service exposure + weak crypto', Tags: ['Delegation', 'WeakEncryption'], AttackTechniques: [{ Id: 'T1550.003', Name: 'Pass the Ticket' }] }
  ],
  adcsTemplates: [{ TemplateName: 'Corp User Smartcard', TemplateShortName: 'CorpUserSmartcard', TemplateDistinguishedName: 'CN=CorpUserSmartcard,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example', PublishedCaNames: ['CORP-CA01'], EnrolleeSuppliesSubject: true, ManagerApprovalRequired: false, RequiredRaSignatures: 0, ExportablePrivateKey: true, ExtendedKeyUsage: ['Client Authentication', 'Smart Card Logon'] }],
  adcsCas: [{ CaName: 'CORP-CA01', CaDistinguishedName: 'CN=CORP-CA01,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example', IsPublished: true, WebEnrollmentEnabled: true }],
  adcsFindings: [
    { AdcsFindingId: 'adcs-demo-000001', Domain: 'corp.example', FindingType: 'AdcsTemplateEscalation', RiskPattern: 'ESC1-style template exposure', EscTechnique: 'ESC1', Severity: 'Critical', RiskScore: 12.6, TemplateName: 'Corp User Smartcard', TemplateShortName: 'CorpUserSmartcard', TemplateDistinguishedName: 'CN=CorpUserSmartcard,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example', PublishedCaNames: ['CORP-CA01'], Principal: 'Domain Users', EnrolleeSuppliesSubject: true, ManagerApprovalRequired: false, RequiredRaSignatures: 0, ExportablePrivateKey: true, ExtendedKeyUsage: ['Client Authentication', 'Smart Card Logon'], Reason: 'Template allows subject supply without approval and can be used for identity impersonation.', Remediation: 'Require manager approval, remove enrollee-supplied subject, and restrict enrollment.', ScoreFormula: 'ADCS score = template exposure + broad enrollment + authentication EKU', Tags: ['ADCS', 'ESC1', 'Authentication'] },
    { AdcsFindingId: 'adcs-demo-000002', Domain: 'corp.example', FindingType: 'AdcsControlDelegation', RiskPattern: 'Template control delegation', Severity: 'High', RiskScore: 8.7, TemplateName: 'Corp User Smartcard', TemplateShortName: 'CorpUserSmartcard', Principal: 'PKI Operators', TargetObjectName: 'Corp User Smartcard', DelegatedRight: 'WriteDacl', Reason: 'Delegated template control can alter issuance settings.', Remediation: 'Restrict template control to dedicated PKI administrators.', ScoreFormula: 'ADCS control score = WriteDacl + authentication template', Tags: ['ADCSControl', 'Delegation'] }
  ],
  trusts: [{ TrustName: 'partner.corp.example', TrustPartner: 'partner.corp.example', TrustDirection: 'Bidirectional', TrustType: 'External', SIDFilteringEnabled: false, SelectiveAuthentication: false, IsTransitive: true, ForestTransitive: false, TGTDelegation: false, DistinguishedName: 'CN=partner.corp.example,CN=System,DC=corp,DC=example', WhenChanged: '2026-06-10T09:00:00-05:00' }],
  trustFindings: [
    { TrustFindingId: 'trust-demo-000001', Domain: 'corp.example', FindingType: 'TrustSidFilteringDisabled', RiskPattern: 'External trust without SID filtering', Severity: 'Critical', RiskScore: 8.8, TrustName: 'partner.corp.example', TrustPartner: 'partner.corp.example', TrustDirection: 'Bidirectional', TrustType: 'External', SIDFilteringEnabled: false, SelectiveAuthentication: false, IsTransitive: true, Reason: 'SID filtering is disabled on an external trust.', Remediation: 'Validate trust requirement, enable SID filtering, and document exceptions.', ScoreFormula: 'Trust score = external trust + SID filtering disabled', Tags: ['TrustBoundary', 'SidFiltering'], AttackTechniques: [{ Id: 'T1134.005', Name: 'SID-History Injection' }] },
    { TrustFindingId: 'trust-demo-000002', Domain: 'corp.example', FindingType: 'TrustSelectiveAuthenticationDisabled', RiskPattern: 'Broad authentication across trust', Severity: 'High', RiskScore: 6.7, TrustName: 'partner.corp.example', TrustPartner: 'partner.corp.example', TrustDirection: 'Bidirectional', TrustType: 'External', SIDFilteringEnabled: false, SelectiveAuthentication: false, IsTransitive: true, Reason: 'Selective authentication is not enabled.', Remediation: 'Enable selective authentication or document compensating controls.', ScoreFormula: 'Trust score = external trust + broad authentication', Tags: ['TrustBoundary', 'SelectiveAuthentication'] }
  ],
  dnsZones: [{ ZoneName: 'corp.example', DynamicUpdate: 'NonsecureAndSecure', AgingEnabled: false, DistinguishedName: 'DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example' }],
  dnsRecords: [
    { ZoneName: 'corp.example', RecordName: '*', RecordType: 'A', RecordData: '10.10.20.50', DistinguishedName: 'DC=*,DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example' },
    { ZoneName: 'corp.example', RecordName: 'old-vpn', RecordType: 'CNAME', RecordData: 'retired-gateway.corp.example', DistinguishedName: 'DC=old-vpn,DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example' }
  ],
  dnsFindings: [
    { DnsFindingId: 'dns-demo-000001', Domain: 'corp.example', FindingType: 'DnsZoneInsecureDynamicUpdate', RiskPattern: 'Zone accepts nonsecure dynamic update', Severity: 'Critical', RiskScore: 8.1, ZoneName: 'corp.example', RecordName: '@', RecordType: 'Zone', RecordData: 'NonsecureAndSecure', ParsedRecordType: 'Zone', ParsedRecordData: 'DynamicUpdate=NonsecureAndSecure', RecordParseStatus: 'Parsed', Principal: 'Authenticated Users', DistinguishedName: 'DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example', Reason: 'Zone allows nonsecure dynamic updates.', Remediation: 'Change dynamic updates to Secure only and review stale records before enforcement.', ScoreFormula: 'DNS score = insecure update + domain-integrated zone', Tags: ['DnsControl', 'DynamicUpdate'] },
    { DnsFindingId: 'dns-demo-000002', Domain: 'corp.example', FindingType: 'DnsWildcardRecord', RiskPattern: 'Wildcard record in internal zone', Severity: 'High', RiskScore: 6.2, ZoneName: 'corp.example', RecordName: '*', RecordType: 'A', RecordData: '10.10.20.50', ParsedRecordType: 'A', ParsedRecordData: '10.10.20.50', RecordParseStatus: 'Parsed', Principal: 'DNS Admins', DistinguishedName: 'DC=*,DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example', Reason: 'Wildcard records can hide mistyped hostnames and redirect unexpected internal traffic.', Remediation: 'Validate owner and remove unapproved wildcard records.', ScoreFormula: 'DNS score = wildcard record + internal zone', Tags: ['DnsHygiene', 'Wildcard'] }
  ],
  objects: [
    { ObjectId: 'obj-demo-000001', DisplayName: 'Archive Backup Service', SamAccountName: 'svc.backup.archive', ObjectClass: 'user', ObjectSid: 'S-1-5-21-demo-5002', DistinguishedName: 'CN=Archive Backup Service,OU=Service Accounts,DC=corp,DC=example', PrivilegeTier: 'Tier 0', Severity: 'Critical', RiskScore: 19.2, EvidenceCount: 3, RelationshipCount: 2, Tags: ['ServiceAccount', 'Tier0', 'Kerberos'], Reason: 'Service account appears in privileged group, Kerberos/Auth, and ACL evidence.' },
    { ObjectId: 'obj-demo-000002', DisplayName: 'AdminSDHolder', SamAccountName: 'AdminSDHolder', ObjectClass: 'container', ObjectSid: 'S-1-5-21-demo-system', DistinguishedName: 'CN=AdminSDHolder,CN=System,DC=corp,DC=example', PrivilegeTier: 'Tier 0', Severity: 'Critical', RiskScore: 12.4, EvidenceCount: 1, RelationshipCount: 1, Tags: ['ACL', 'ProtectedObjects'], Reason: 'Unexpected WriteDacl path impacts protected accounts.' },
    { ObjectId: 'obj-demo-000003', DisplayName: 'Tier 0 Workstation Control Policy', SamAccountName: 'DEMO-GPO-0001', ObjectClass: 'groupPolicyContainer', ObjectSid: '', DistinguishedName: 'CN={DEMO-GPO-0001},CN=Policies,CN=System,DC=corp,DC=example', PrivilegeTier: 'Tier 0', Severity: 'Critical', RiskScore: 26.7, EvidenceCount: 2, RelationshipCount: 2, Tags: ['GPO', 'Tier0Scope'], Reason: 'GPO affects Domain Controllers and has broad delegation and credential exposure evidence.' }
  ],
  objectEvidence: [
    { ObjectId: 'obj-demo-000001', EvidenceType: 'SensitiveGroup', FindingId: 'finding-demo-000002', Reason: 'Nested path to Domain Admins.' },
    { ObjectId: 'obj-demo-000001', EvidenceType: 'KerberosAuth', FindingId: 'auth-demo-000001', Reason: 'Roastable service account with weak encryption.' },
    { ObjectId: 'obj-demo-000002', EvidenceType: 'ACL', FindingId: 'acl-demo-000001', Reason: 'WriteDacl on AdminSDHolder.' },
    { ObjectId: 'obj-demo-000003', EvidenceType: 'GPO', FindingId: 'gpo-demo-000001', Reason: 'GenericAll over a Tier 0-linked GPO.' }
  ],
  objectRelationships: [
    { SourceObjectId: 'obj-demo-000001', TargetObjectId: 'obj-demo-000003', RelationshipType: 'CanAffect', Reason: 'Service account can influence backup infrastructure tied to Tier 0 operations.' },
    { SourceObjectId: 'obj-demo-000003', TargetObjectId: 'obj-demo-000002', RelationshipType: 'Tier0Scope', Reason: 'Policy applies to Domain Controllers and protected identity workflows.' }
  ],
  meta: {
    sensitivity: 'Synthetic demo data only. Safe for public screenshots.',
    domain: 'corp.example', forest: 'corp.example', auditedBy: 'CORP\\demo.analyst', timestamp: '2026-06-10T09:00:00-05:00', overallRiskScore: 37.0, targetScore: 0,
    actionableCount: 6, approvedExceptionCount: 1, expiredExceptionCount: 1,
    tierBreakdown: { 'Tier 0': 4, 'Tier 1': 1, 'Tier 2': 1 }, remediation: { High: 2, Medium: 3, Low: 1 },
    readiness: { Score: 68, Controls: [
      { Name: 'Tier 0 standing access', Status: 'Fail', Count: 4, Target: 0, Detail: 'Reduce permanent Tier 0 memberships and route access through approval.' },
      { Name: 'Service account privilege', Status: 'Review', Count: 2, Target: 0, Detail: 'Reduce standing service account privilege and require approved ownership.' },
      { Name: 'Native identity handling', Status: 'Pass', Count: 1, Target: 0, Detail: 'Native AD principals are separated from normal remediation.' },
      { Name: 'Approved exceptions', Status: 'Review', Count: 1, Target: 0, Detail: 'One exception needs renewal or removal.' }
    ] }
  }
};
