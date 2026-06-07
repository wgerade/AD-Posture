$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

function Get-ModuleConfig {
    [pscustomobject]@{
        DataPath = $TestDrive
    }
}

function Write-ADPostureTimelineDashboardData {
    param($TimelineData)
    $script:LastTimelineData = $TimelineData
}

. (Join-Path $repoRoot 'src\Private\Protect-ADPostureFile.ps1')
. (Join-Path $repoRoot 'src\Private\Get-ADPostureTimelineHistoryPoints.ps1')
. (Join-Path $repoRoot 'src\Public\Compare-ADPostureSnapshots.ps1')
. (Join-Path $repoRoot 'src\Public\Compare-ADPostureSnapshotsFullHistory.ps1')

Describe 'Timeline ACL drift comparison' {
    It 'compares ACL findings and marks drift states' {
        $baselinePath = Join-Path $TestDrive 'baseline.json'
        $currentPath = Join-Path $TestDrive 'current.json'

        $baseline = [pscustomobject]@{
            Timestamp = '2026-05-24T10:00:00Z'
            OverallRiskScore = 10
            ActionableCount = 2
            Findings = @()
            AclFindings = @(
                [pscustomobject]@{
                    Domain = 'contoso.local'
                    NormalizedRight = 'WriteDacl'
                    TrusteeName = 'Legacy Admins'
                    TargetName = 'AdminSDHolder'
                    TargetDistinguishedName = 'CN=AdminSDHolder,CN=System,DC=contoso,DC=local'
                    ObjectType = '00000000-0000-0000-0000-000000000000'
                    RiskScore = 10
                    Severity = 'High'
                    IsInherited = $false
                },
                [pscustomobject]@{
                    Domain = 'contoso.local'
                    NormalizedRight = 'GenericAll'
                    TrusteeName = 'Old Delegates'
                    TargetName = 'Old Target'
                    TargetDistinguishedName = 'CN=Old Target,DC=contoso,DC=local'
                    ObjectType = '00000000-0000-0000-0000-000000000000'
                    RiskScore = 8
                    Severity = 'High'
                    IsInherited = $false
                }
            )
        }

        $current = [pscustomobject]@{
            Timestamp = '2026-05-25T10:00:00Z'
            OverallRiskScore = 15
            ActionableCount = 3
            Findings = @()
            AclFindings = @(
                [pscustomobject]@{
                    Domain = 'contoso.local'
                    NormalizedRight = 'WriteDacl'
                    TrusteeName = 'Legacy Admins'
                    TargetName = 'AdminSDHolder'
                    TargetDistinguishedName = 'CN=AdminSDHolder,CN=System,DC=contoso,DC=local'
                    ObjectType = '00000000-0000-0000-0000-000000000000'
                    RiskScore = 10
                    Severity = 'High'
                    IsInherited = $false
                },
                [pscustomobject]@{
                    Domain = 'contoso.local'
                    NormalizedRight = 'DCSync'
                    TrusteeName = 'Sync Operators'
                    TargetName = 'contoso.local'
                    TargetDistinguishedName = 'DC=contoso,DC=local'
                    ObjectType = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
                    RiskScore = 15
                    Severity = 'Critical'
                    IsInherited = $false
                }
            )
        }

        $baseline | ConvertTo-Json -Depth 8 | Set-Content -Path $baselinePath -Encoding UTF8
        $current | ConvertTo-Json -Depth 8 | Set-Content -Path $currentPath -Encoding UTF8
        [void](Write-ADPostureFileHashSidecar -Path $baselinePath)
        [void](Write-ADPostureFileHashSidecar -Path $currentPath)

        $timeline = Compare-ADPostureSnapshots -BaselinePath $baselinePath -CurrentPath $currentPath

        $timeline.IntegrityStatus | Should Be 'Valid'
        $timeline.AclAddedCount | Should Be 1
        $timeline.AclRemovedCount | Should Be 1
        $timeline.AclUnchangedCount | Should Be 1
        $timeline.AclNewCriticalHighCount | Should Be 1
        $timeline.AclAdded[0].DriftState | Should Be 'New'
        $timeline.AclRemoved[0].DriftState | Should Be 'Missing'
        $timeline.AclUnchanged[0].DriftState | Should Be 'Unchanged'
        $timeline.History[1].aclFindings | Should Be 2
        $script:LastTimelineData.AclAddedCount | Should Be 1
    }

    It 'marks timeline integrity warnings when a sidecar hash mismatches' {
        $baselinePath = Join-Path $TestDrive 'baseline-mismatch.json'
        $currentPath = Join-Path $TestDrive 'current-mismatch.json'
        $baseline = [pscustomobject]@{ Timestamp = '2026-05-24T10:00:00Z'; OverallRiskScore = 1; ActionableCount = 1; Findings = @(); AclFindings = @() }
        $current = [pscustomobject]@{ Timestamp = '2026-05-25T10:00:00Z'; OverallRiskScore = 2; ActionableCount = 2; Findings = @(); AclFindings = @() }

        $baseline | ConvertTo-Json -Depth 8 | Set-Content -Path $baselinePath -Encoding UTF8
        $current | ConvertTo-Json -Depth 8 | Set-Content -Path $currentPath -Encoding UTF8
        [void](Write-ADPostureFileHashSidecar -Path $baselinePath)
        [void](Write-ADPostureFileHashSidecar -Path $currentPath)
        $current | Add-Member -NotePropertyName Extra -NotePropertyValue 'changed' -Force
        $current | ConvertTo-Json -Depth 8 | Set-Content -Path $currentPath -Encoding UTF8

        $timeline = Compare-ADPostureSnapshots -BaselinePath $baselinePath -CurrentPath $currentPath -WarningAction SilentlyContinue

        $timeline.IntegrityStatus | Should Be 'Warning'
        @($timeline.IntegrityWarnings).Count | Should Be 1
        $timeline.Integrity.Current.Status | Should Be 'Mismatch'
    }

    It 'builds full timeline history while skipping invalid snapshots' {
        1..3 | ForEach-Object {
            $path = Join-Path $TestDrive "snapshot-2026050$_.json"
            [pscustomobject]@{
                SchemaVersion = '1.2'
                AuditId = "audit-$_"
                Timestamp = "2026-05-0$($_)T10:00:00Z"
                Domain = 'contoso.local'
                Forest = 'contoso.local'
                OverallRiskScore = $_
                ActionableCount = $_
                AclFindings = @()
            } | ConvertTo-Json -Depth 4 | Set-Content -Path $path -Encoding UTF8
            [void](Write-ADPostureFileHashSidecar -Path $path)
        }
        Add-Content -LiteralPath (Join-Path $TestDrive 'snapshot-20260502.json') -Value 'tampered'

        $history = Get-ADPostureTimelineHistoryPoints -DataDirectory $TestDrive -WarningAction SilentlyContinue

        @($history).Count | Should Be 2
        @($history.auditId) -contains 'audit-1' | Should Be $true
        @($history.auditId) -contains 'audit-3' | Should Be $true
        @($history.auditId) -contains 'audit-2' | Should Be $false
    }

    It 'enriches automatic comparison with all valid history and current metadata' {
        1..3 | ForEach-Object {
            Start-Sleep -Milliseconds 20
            $path = Join-Path $TestDrive "snapshot-2026060$_.json"
            [pscustomobject]@{
                SchemaVersion = '1.2'
                AuditId = "june-audit-$_"
                Timestamp = "2026-06-0$($_)T10:00:00Z"
                Domain = 'contoso.local'
                Forest = 'contoso.local'
                TargetScore = 0
                OverallRiskScore = $_
                ActionableCount = $_
                Findings = @()
                AclFindings = @()
            } | ConvertTo-Json -Depth 4 | Set-Content -Path $path -Encoding UTF8
            [void](Write-ADPostureFileHashSidecar -Path $path)
            (Get-Item -LiteralPath $path).LastWriteTime = (Get-Date).AddMinutes($_)
        }

        $timeline = Compare-ADPostureSnapshots -UseLatestTwo -DataDirectory $TestDrive

        @($timeline.History).Count | Should Be 5
        $timeline.CurrentAuditId | Should Be 'june-audit-3'
        $timeline.Domain | Should Be 'contoso.local'
        $timeline.SchemaVersion | Should Be '1.2'
        @($script:LastTimelineData.History).Count | Should Be 5
    }
}
