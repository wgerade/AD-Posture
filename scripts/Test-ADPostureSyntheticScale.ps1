[CmdletBinding()]
param(
    [ValidateRange(100, 1000000)]
    [int] $FindingCount = 10000,

    [ValidateRange(10, 100000)]
    [int] $GroupCount = 1000,

    [int] $Seed = 42,

    [string] $OutputPath
)

$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'ADPosture.psd1') -Force
$random = [System.Random]::new($Seed)
$groups = 1..$GroupCount | ForEach-Object {
    [pscustomobject]@{ SensitiveGroup = "Synthetic-Group-$_"; MemberCount = if ($_ % 20 -eq 0) { 0 } else { $random.Next(1, 50) }; PrivilegeTier = if ($_ % 5 -eq 0) { 'Tier 0' } else { 'Tier 1' } }
}
$findings = 1..$FindingCount | ForEach-Object {
    [pscustomobject]@{ FindingId = "synthetic-$_"; FindingType = 'SensitiveGroupMembership'; SensitiveGroup = "Synthetic-Group-$($random.Next(1, $GroupCount + 1))"; MemberSam = "account-$_"; MemberDisplay = "account-$_"; MemberDn = "CN=account-$_,DC=synthetic,DC=local"; IsDirect = $true; TruncatedNesting = $false; RiskScore = [double](($_ % 10) + 1); Severity = if ($_ % 10 -ge 7) { 'High' } else { 'Medium' }; RemediationDifficulty = 'Medium' }
}
$snapshot = [pscustomobject]@{
    SchemaVersion = '1.1'; AuditId = [guid]::NewGuid().ToString(); Timestamp = (Get-Date).ToString('o'); Domain = 'synthetic.local'
    GroupSummaries = @($groups); Findings = @($findings); AclFindings = @(); GpoFindings = @(); AdcsFindings = @(); KerberosAuthFindings = @()
    TrustFindings = @(); DnsFindings = @(); IdentityRiskFindings = @(); Objects = @(); ObjectEvidence = @(); ObjectRelationships = @()
    OverallRiskScore = 0; ActionableCount = 0; ApprovedExceptionCount = 0; ExpiredExceptionCount = 0
}
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$updated = & (Get-Module ADPosture) { param($s) Update-ADPostureSnapshotV12 -Snapshot $s } $snapshot
$stopwatch.Stop()
$expectedOrphans = [Math]::Floor($GroupCount / 20)
$result = [pscustomobject]@{
    Seed = $Seed; InputFindings = $FindingCount; Groups = $GroupCount
    ExpectedOrphans = $expectedOrphans; ActualOrphans = @($updated.OrphanedSensitiveGroupFindings).Count
    Playbooks = @($updated.RemediationPlaybooks).Count; FrameworkMappings = @($updated.FrameworkSummary).Count
    ElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
    FindingsPerSecond = if ($stopwatch.Elapsed.TotalSeconds -gt 0) { [Math]::Round($FindingCount / $stopwatch.Elapsed.TotalSeconds, 2) } else { 0 }
    AccuracyPassed = (@($updated.OrphanedSensitiveGroupFindings).Count -eq $expectedOrphans)
}
if ($OutputPath) { $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding UTF8 }
$result
