/* Synthetic demo timeline data for the public AD Posture guided tour. */
window.__AD_TIMELINE_DATA__ = {
  ScoreBefore: 42.6,
  ScoreAfter: 37.0,
  ScoreDelta: -5.6,
  AddedCount: 2,
  RemovedCount: 3,
  ChangedCount: 2,
  History: [
    { timestamp: '2026-03-01T09:00:00-05:00', score: 58.4, actionable: 15 },
    { timestamp: '2026-04-01T09:00:00-05:00', score: 47.2, actionable: 12 },
    { timestamp: '2026-05-01T09:00:00-05:00', score: 42.6, actionable: 10 },
    { timestamp: '2026-06-10T09:00:00-05:00', score: 37.0, actionable: 6 }
  ],
  Added: [
    { Status: 'Added', SensitiveGroup: 'Domain Admins', MemberDisplay: 'Archive Backup Service', MemberSam: 'svc.backup.archive', MembershipChain: 'Domain Admins -> Backup Operators -> Archive Backup Service', RiskScore: 9.8 },
    { Status: 'Added', SensitiveGroup: 'Group Policy Creator Owners', MemberDisplay: 'Jane Admin', MemberSam: 'jane.admin', MembershipChain: 'Group Policy Creator Owners -> Jane Admin', RiskScore: 5.9 }
  ],
  Removed: [
    { Status: 'Removed', SensitiveGroup: 'Domain Admins', MemberDisplay: 'Retired Domain Admin', MemberSam: 'retired.domain.admin', MembershipChain: 'Domain Admins -> Retired Domain Admin', RiskScore: 7.2 },
    { Status: 'Removed', SensitiveGroup: 'Backup Operators', MemberDisplay: 'Old Backup Service', MemberSam: 'old.backup.svc', MembershipChain: 'Backup Operators -> Old Backup Service', RiskScore: 4.1 },
    { Status: 'Removed', SensitiveGroup: 'Remote Desktop Users', MemberDisplay: 'Former Contractor', MemberSam: 'former.contractor', MembershipChain: 'Remote Desktop Users -> Former Contractor', RiskScore: 2.7 }
  ],
  Changed: [
    { Before: '9.80', After: '4.20', Finding: { SensitiveGroup: 'Backup Operators', MemberDisplay: 'File Backup gMSA', MemberSam: 'svc.file.backup', MembershipChain: 'Backup Operators -> File Backup gMSA', RiskScore: 4.2 } },
    { Before: '6.60', After: '2.10', Finding: { SensitiveGroup: 'Remote Desktop Users', MemberDisplay: 'Contractor Ops', MemberSam: 'contractor.ops', MembershipChain: 'Remote Desktop Users -> Contractor Ops', RiskScore: 2.1 } }
  ],
  AclAdded: [
    { Status: 'Added', ActiveDirectoryRights: 'WriteDacl', TrusteeName: 'Delegated Admins', TargetName: 'AdminSDHolder', RiskScore: 12.4 }
  ],
  AclRemoved: [
    { Status: 'Removed', ActiveDirectoryRights: 'GenericAll', TrusteeName: 'Legacy Operators', TargetName: 'Domain Admins', RiskScore: 10.2 }
  ]
};
